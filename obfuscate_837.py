#!/usr/bin/env python3
"""
obfuscate_837.py  (v4) — obfuscate PHI in X12 837 claim files (837P and 837I).

Three modes (--mode):

  basic (default)   Patient identity only.  Everything else in the claim is left exactly
                    as it was: service dates, claim/line control numbers, provider names,
                    ZIP codes, envelope.  Fine-grained flags let you add more.

  expert            The transformations an Expert Determination (45 CFR 164.514(b)(1))
                    normally relies on, keeping as much of the claim as possible:
                    basic + per-patient date shifting, claim/line/auth numbers replaced,
                    NPI-less person providers (aides, relatives) renamed, ZIP cut to the
                    first 3 digits.  Pseudonyms are a keyed hash (HMAC) of the real value —
                    HHS allows that under Expert Determination as long as the key is not
                    disclosed, so the --seed is part of the de-identification: keep it
                    secret.  NOTE: only an expert's written determination makes a data set
                    de-identified under (b)(1); this mode applies the usual techniques, it
                    cannot grant the determination.

  safe-harbor       45 CFR 164.514(b)(2) Safe Harbor.  Ignores every other option.

Run with -h for a side-by-side table of what each mode changes.  Run with NO arguments
(double-click the file) to get a window instead of the command line; a copy named
obfuscate_837.pyw opens the window without a console on Windows.

Everything that is not PHI (envelope, submitter/receiver, billing & pay-to provider,
payer, NPIs, tax IDs, procedure/diagnosis codes, charges, units, modifiers, place of
service, segment order, delimiters, line endings, segment counts) is left byte-for-byte
as it was.  Replacement values always have the same shape (length / digit-letter
pattern / date format) as the original, so the file still parses.

Names are drawn from two separate tables — one for the patient/subscriber/dependent,
one for everybody else (relatives named in NTE notes, aides, contact persons) — so a
relative who really shares the patient's surname never shares the patient's FAKE name,
and a note can never name the fake patient.  Within a table the mapping is consistent:
the same real person gets the same fake name in every file.

BASIC MODE — what is changed
-----------------------------
Inside the subscriber/patient hierarchy (after the first HL*..*22 of each 2000A loop):

  NM1 IL / QC (and 2330A other-subscriber IL): last, first, middle name and NM109 ID
       (member ID / SSN).   SBR03 too when it repeats the member ID (Indiana Medicaid
       files do this).
  N3  street.   N4 city; county code dropped; STATE and ZIP kept.
  PER contact after an obfuscated person: name / phone / fax / email.
  DMG date of birth: shifted by a per-person offset of +-1..730 days, clamped so no
       fake age exceeds 89.
  REF EA (MRN), SY (SSN), 1W, 23, IG.
  NTE / K3 free text: "NAME ... REL ..." relatives and any patient-name token are
       swapped for fakes; digit runs of 5+ are re-randomized.

  Opt-ins (all on in expert mode):
    --shift-service-dates [--date-shift-days N]   DTP / HI / PAT dates back 1..N days
                                                  per patient (default N = 60)
    --scramble-claim-ids        CLM01, PWK06 and REF 6R / G1 / 9F / F8 / D9
    --scramble-provider-names   person providers (NM102=1) that carry NO NPI
    --zip-mode zip3|random      (basic default keep, expert default zip3)
    --id-keep-tail N            keep the last N chars of member IDs (payer formats)

Mapping is DETERMINISTIC in basic/expert mode: same real value -> same fake value within
a run, and across runs with the same --seed.

SAFE HARBOR MODE
----------------
Implements 164.514(b)(2)(i)(A)-(R) for the data an 837 can carry:

  (A) names            patient, subscriber, dependent, other-subscriber, any person
                       provider without an NPI, PER contact names -> random names
  (B) geography        street, city, county removed (random placeholders); state kept;
                       ZIP reduced to its first 3 digits + "00", or "00000" when the
                       3-digit area is on the HHS restricted list (population < 20,000)
  (C) dates            every DTP, HI occurrence/span/value date, PAT death date, and
                       DMG birth date reduced to YEAR ONLY (written as YYYY0101 so the
                       field stays valid X12); times zeroed.  Ages > 89 are collapsed
                       into "90+" by writing a birth year exactly 90 years before the
                       file's GS date.  Envelope dates (ISA09/10, GS04/05, BHT04/05) are
                       reduced to year as well, because in a one-claim file they are a
                       proxy for the service date.
  (D)(E)(F) phone / fax / email  -> replaced
  (G) SSN, (H) MRN, (I) plan beneficiary number, (J) account number,
  (R) other unique numbers      -> NM109, SBR03, REF SY/EA/1W/23/IG/6R/G1/9F/F8/D9,
                                   CLM01, PWK06 replaced with RANDOM values of the same shape
  free text            NTE and K3 text replaced with "REDACTED" (no regex scrubbing —
                       Safe Harbor makes no exception for free text)

  Pseudonyms in this mode are drawn from os.urandom, NOT derived from the real value,
  because HHS treats any code derived from PHI (including an unkeyed hash) as an
  identifier.  Consistency across runs is only possible by re-loading a saved mapping
  (--map on the first run, --map-in on later runs).  That mapping file is the
  re-identification key under 164.514(c): keep it inside the covered entity.

  What this mode cannot do for you: 164.514(b)(2)(ii) — the covered entity must have no
  ACTUAL KNOWLEDGE that the remaining data (diagnosis codes, provider NPIs, state,
  year, charges) could identify someone.  Review that before releasing the output.

USAGE
-----
  python3 obfuscate_837.py INPUT [INPUT ...] -o OUTDIR
  python3 obfuscate_837.py ./837_files -o ./837_test --seed "my secret"
  python3 obfuscate_837.py ./837_files -o ./837_expert --mode expert --seed "my secret"
  python3 obfuscate_837.py ./837_files -o ./837_deid --mode safe-harbor --map key.csv
  python3 obfuscate_837.py claim.dat --in-place --shift-service-dates --scramble-claim-ids

INPUT may be files or directories (directories are walked recursively; the directory
layout is reproduced under OUTDIR).  Standard library only.
"""

import argparse
import csv
import hashlib
import hmac
import os
import random
import re
import secrets
import sys
from datetime import date, datetime, timedelta

# --------------------------------------------------------------------------------------
# Fake data pools
# --------------------------------------------------------------------------------------
FIRST_NAMES = """
AARON ABIGAIL ADAM ADDISON ADELE ADRIAN ADRIANA AGNES AIDAN AIMEE ALAN ALBERT ALBERTA ALEC
ALEJANDRO ALEX ALEXA ALEXANDER ALEXANDRA ALEXIS ALFRED ALFREDO ALICE ALICIA ALINA ALISON
ALLAN ALLEN ALLISON ALMA ALONZO ALTON ALVIN ALYSSA AMANDA AMBER AMELIA AMOS AMY ANA ANDRE
ANDREA ANDRES ANDREW ANDY ANGEL ANGELA ANGELINA ANGELO ANGIE ANITA ANN ANNA ANNE ANNETTE
ANNIE ANTHONY ANTONIA ANTONIO APRIL ARCHIE ARIANA ARIEL ARLENE ARMANDO ARNOLD ARTHUR ARTURO
ASHLEY AUBREY AUDREY AUGUST AURORA AUSTIN AVA AVERY BARBARA BARRY BEATRICE BECKY BELINDA
BEN BENJAMIN BENNIE BERNADETTE BERNARD BERNICE BERT BERTHA BESSIE BETH BETSY BETTY BEULAH
BEVERLY BILL BILLIE BILLY BLAKE BLANCHE BOB BOBBIE BOBBY BONNIE BOYD BRAD BRADLEY BRADY
BRANDI BRANDON BRANDY BRENDA BRENDAN BRENT BRETT BRIAN BRIANNA BRIDGET BRITTANY BROOKE
BRUCE BRYAN BRYCE BYRON CAITLIN CALEB CALVIN CAMERON CAMILLE CANDACE CANDICE CARA CARL
CARLA CARLOS CARLTON CARMEN CAROL CAROLE CAROLINE CAROLYN CARRIE CARROLL CARSON CARTER
CARY CASEY CASSANDRA CATHERINE CATHY CECIL CECILIA CEDRIC CELIA CESAR CHAD CHARLENE CHARLES
CHARLIE CHARLOTTE CHELSEA CHERYL CHESTER CHLOE CHRIS CHRISTIAN CHRISTINA CHRISTINE
CHRISTOPHER CHRISTY CINDY CLAIRE CLARA CLARENCE CLARK CLAUDE CLAUDIA CLAY CLAYTON CLIFFORD
CLIFTON CLINT CLINTON CLYDE CODY COLE COLIN COLLEEN CONNIE CONNOR CONRAD CONSTANCE CORA
COREY CORNELIUS CORY COURTNEY CRAIG CRYSTAL CURTIS CYNTHIA DAISY DALE DALLAS DAMON DAN DANA
DANIEL DANIELLE DANNY DAPHNE DARLA DARLENE DARNELL DARREN DARRYL DARYL DAVE DAVID DAWN DEAN
DEANNA DEBBIE DEBORAH DEBRA DELBERT DELIA DELORES DENISE DENNIS DEREK DERRICK DESIREE DEVIN
DEWEY DEXTER DIANA DIANE DIANNE DOLORES DOMINIC DON DONALD DONNA DONNIE DORA DOREEN DORIS
DOROTHY DOUG DOUGLAS DOYLE DREW DUANE DUSTIN DWAYNE DWIGHT DYLAN EARL EARNEST EDDIE EDGAR
EDITH EDMOND EDMUND EDNA EDUARDO EDWARD EDWIN EILEEN ELAINE ELBERT ELEANOR ELENA ELI ELIAS
ELIJAH ELISE ELIZABETH ELLA ELLEN ELLIOT ELLIS ELMER ELOISE ELSA ELSIE ELVIRA EMANUEL EMILY
EMMA EMMETT ENRIQUE ERIC ERICA ERIK ERIKA ERIN ERMA ERNEST ERNESTINE ERVIN ESTELLE ESTHER
ETHAN ETHEL EUGENE EULA EUNICE EVA EVAN EVELYN EVERETT FAITH FANNIE FAYE FELICIA FELIX
FERNANDO FLORA FLORENCE FLOYD FORREST FRANCES FRANCIS FRANCISCO FRANK FRANKIE FRANKLIN FRED
FREDA FREDDIE FREDERICK FREDRICK GABRIEL GAIL GARRETT GARRY GARY GAYLE GENE GENEVA GENEVIEVE
GEOFFREY GEORGE GEORGIA GERALD GERALDINE GERARD GERTRUDE GILBERT GINA GINGER GLADYS GLEN
GLENDA GLENN GLORIA GORDON GRACE GRADY GRANT GREG GREGG GREGORY GRETCHEN GUADALUPE GUY
GWEN GWENDOLYN HANNAH HARLAN HAROLD HARRIET HARRY HARVEY HATTIE HAZEL HEATHER HECTOR HEIDI
HELEN HENRIETTA HENRY HERBERT HERMAN HILDA HOLLY HOMER HOPE HORACE HOWARD HUBERT HUGH HUGO
IAN IDA IGNACIO INEZ IRA IRENE IRIS IRMA IRVING ISAAC ISABEL ISMAEL IVAN JACK JACKIE JACKSON
JACOB JACQUELINE JAIME JAKE JAMES JAMIE JAN JANA JANE JANET JANICE JANIE JANIS JARED JASMINE
JASON JAVIER JAY JEAN JEANETTE JEANNE JEANNETTE JEFF JEFFERY JEFFREY JENNA JENNIE JENNIFER
JENNY JEREMIAH JEREMY JERMAINE JEROME JERRY JESSE JESSICA JESSIE JESUS JILL JIM JIMMIE JIMMY
JO JOAN JOANN JOANNA JOANNE JODY JOE JOEL JOEY JOHANNA JOHN JOHNNIE JOHNNY JON JONATHAN
JORDAN JORGE JOSE JOSEPH JOSEPHINE JOSH JOSHUA JOY JOYCE JUAN JUANA JUANITA JUDITH JUDY JULIA
JULIAN JULIE JULIO JULIUS JUNE JUSTIN KARA KAREN KARI KARL KARLA KATE KATHERINE KATHLEEN
KATHRYN KATHY KATIE KATRINA KAY KAYLA KEITH KELLEY KELLI KELLY KELVIN KEN KENDRA KENNETH
KENNY KENT KERRY KEVIN KIM KIMBERLY KIRK KRISTEN KRISTI KRISTIN KRISTINA KRISTINE KRISTY
KURT KYLE LAMAR LANA LANCE LARRY LATOYA LAURA LAUREN LAURIE LAVERNE LAWRENCE LEAH LEE LEIGH
LELA LELAND LENA LEO LEON LEONA LEONARD LEROY LESLIE LESTER LETICIA LEVI LEWIS LILA LILLIAN
LILLIE LINDA LINDSAY LINDSEY LIONEL LISA LLOYD LOIS LOLA LONNIE LORA LOREN LORENA LORENZO
LORETTA LORI LORRAINE LOUIS LOUISE LOWELL LUCAS LUCILLE LUCY LUIS LUKE LULA LUTHER LYDIA
LYLE LYNDA LYNN LYNNE MABEL MACK MADELINE MAE MAGGIE MALCOLM MAMIE MANDY MANUEL MARC MARCELLA
MARCIA MARCO MARCOS MARCUS MARGARET MARGARITA MARGIE MARGUERITE MARIA MARIAN MARIANNE MARIE
MARILYN MARIO MARION MARJORIE MARK MARLENE MARSHA MARSHALL MARTA MARTHA MARTIN MARTY MARVIN
MARY MARYANN MATHEW MATT MATTHEW MATTIE MAUREEN MAURICE MAX MAXINE MAY MEGAN MEGHAN MELANIE
MELBA MELINDA MELISSA MELODY MELVIN MERCEDES MEREDITH MERLE MICHAEL MICHEAL MICHELE MICHELLE
MIGUEL MIKE MILDRED MILTON MINDY MINNIE MIRANDA MIRIAM MISTY MITCHELL MOLLY MONA MONICA
MONIQUE MORRIS MOSES MURIEL MYRA MYRON MYRTLE NADINE NANCY NAOMI NATALIE NATASHA NATHAN
NATHANIEL NEAL NEIL NELLIE NELSON NETTIE NICHOLAS NICK NICOLE NINA NOAH NOEL NORA NORMA
NORMAN OLGA OLIVE OLIVER OLIVIA OLLIE OMAR OPAL ORA ORLANDO ORVILLE OSCAR OTIS OWEN PABLO
PAM PAMELA PAT PATRICIA PATRICK PATSY PATTI PATTY PAUL PAULA PAULETTE PAULINE PEARL PEDRO
PEGGY PENNY PERCY PERRY PETE PETER PHIL PHILIP PHILLIP PHYLLIS PRESTON PRISCILLA RACHAEL
RACHEL RAFAEL RALPH RAMIRO RAMON RAMONA RANDAL RANDALL RANDOLPH RANDY RAQUEL RAUL RAY
RAYMOND REBA REBECCA REGINA REGINALD RENE RENEE REX RHONDA RICARDO RICHARD RICK RICKY RITA
ROBERT ROBERTA ROBERTO ROBIN ROBYN ROCHELLE RODERICK RODNEY ROGELIO ROGER ROLAND ROMAN RON
RONALD RONNIE ROOSEVELT ROSA ROSALIE ROSALIND ROSEMARIE ROSEMARY ROSIE ROSS ROXANNE ROY
RUBEN RUBY RUDOLPH RUDY RUFUS RUSSELL RUSTY RUTH RYAN SABRINA SADIE SALLY SALVADOR SAM
SAMANTHA SAMMY SAMUEL SANDRA SANDY SANTIAGO SARA SARAH SAUL SCOTT SEAN SERGIO SETH SHANE
SHANNON SHARI SHARON SHAUN SHAWN SHEILA SHELBY SHELDON SHELIA SHELLEY SHELLY SHERI SHERMAN
SHERRI SHERRY SHERYL SHIRLEY SIDNEY SILVIA SIMON SONIA SONJA SONYA SOPHIA SOPHIE SPENCER
STACEY STACY STANLEY STELLA STEPHANIE STEPHEN STEVE STEVEN STEWART STUART SUE SUSAN SUSIE
SUZANNE SYLVESTER SYLVIA TABITHA TAMARA TAMI TAMMY TANYA TARA TASHA TAYLOR TED TERENCE
TERESA TERRANCE TERRELL TERRENCE TERRI TERRY THELMA THEODORE THERESA THOMAS TIFFANY TIM
TIMOTHY TINA TODD TOM TOMMY TONI TONY TONYA TRACEY TRACI TRACY TRAVIS TRENT TREVOR TRICIA
TROY TYLER TYRONE VALERIE VANESSA VELMA VERA VERNA VERNON VERONICA VICKI VICKIE VICKY VICTOR
VICTORIA VINCENT VIOLA VIOLET VIRGIL VIRGINIA VIVIAN WADE WALLACE WALTER WANDA WARREN WAYNE
WENDELL WENDY WESLEY WHITNEY WILBERT WILBUR WILLARD WILLIAM WILLIE WILLIS WILMA WILSON
WINIFRED WINSTON WOODROW YOLANDA YVETTE YVONNE ZACHARY
""".split()

LAST_NAMES = """
ABBOTT ABERNATHY ACEVEDO ACOSTA ADAMS ADKINS AGUILAR AGUIRRE ALBERT ALEXANDER ALFORD ALLEN
ALLISON ALSTON ALVARADO ALVAREZ ANDERSON ANDREWS ANTHONY ARMSTRONG ARNOLD ARROYO ASHLEY
ATKINS ATKINSON AUSTIN AVERY AVILA AYALA AYERS BAILEY BAIRD BAKER BALDWIN BALL BALLARD BANKS
BARBER BARKER BARLOW BARNES BARNETT BARR BARRERA BARRETT BARRON BARRY BARTLETT BARTON BASS
BATES BATTLE BAUER BAXTER BEACH BEAN BEARD BEASLEY BECK BECKER BELL BENDER BENJAMIN BENNETT
BENSON BENTLEY BENTON BERG BERGER BERNARD BERRY BEST BIRD BISHOP BLACK BLACKBURN BLACKWELL
BLAIR BLAKE BLANCHARD BLANKENSHIP BLEVINS BOLTON BOND BONNER BOOKER BOONE BOOTH BOWEN BOWERS
BOWMAN BOYD BOYER BOYLE BRADFORD BRADLEY BRADSHAW BRADY BRANCH BRANDT BRAY BRENNAN BREWER
BRIDGES BRIGGS BRIGHT BRITT BROCK BROOKS BROWN BROWNING BRUCE BRYAN BRYANT BUCHANAN BUCK
BUCKLEY BUCKNER BULLOCK BURCH BURGESS BURKE BURKS BURNETT BURNS BURRIS BURT BURTON BUSH
BUTLER BYERS BYRD CABRERA CAIN CALDERON CALDWELL CALHOUN CALLAHAN CAMACHO CAMERON CAMPBELL
CAMPOS CANNON CANTRELL CANTU CARDENAS CARDONA CAREY CARLSON CARNEY CARPENTER CARR CARRILLO
CARROLL CARSON CARTER CARVER CASE CASEY CASH CASTANEDA CASTILLO CASTRO CERVANTES CHAMBERS
CHAN CHANDLER CHANEY CHANG CHAPMAN CHARLES CHASE CHAVEZ CHEN CHERRY CHRISTENSEN CHRISTIAN
CHURCH CLARK CLARKE CLAY CLAYTON CLEMENTS CLEMONS CLEVELAND CLINE COBB COCHRAN COFFEY COHEN
COLE COLEMAN COLLIER COLLINS COLON COMBS COMPTON CONLEY CONNER CONRAD CONTRERAS CONWAY COOK
COOKE COOLEY COOPER COPELAND CORTEZ COTE COTTON COX CRAFT CRAIG CRANE CRAWFORD CROSBY CROSS
CRUZ CUMMINGS CUNNINGHAM CURRY CURTIS DALE DALTON DANIEL DANIELS DAUGHERTY DAVENPORT DAVID
DAVIDSON DAVIS DAWSON DAY DEAN DECKER DEJESUS DELACRUZ DELANEY DELEON DELGADO DENNIS DICKERSON
DICKSON DILLARD DILLON DIXON DODSON DOMINGUEZ DONALDSON DONOVAN DORSEY DOTSON DOUGLAS DOWNS
DOYLE DRAKE DUDLEY DUFFY DUKE DUNCAN DUNLAP DUNN DURAN DURHAM DYER EATON EDWARDS ELLIOTT
ELLIS ELLISON EMERSON ENGLAND ENGLISH ERICKSON ESPINOZA ESTES ESTRADA EVANS EVERETT EWING
FARLEY FARMER FARRELL FAULKNER FERGUSON FERNANDEZ FERRELL FIELDS FIGUEROA FINCH FINLEY
FISCHER FISHER FITZGERALD FITZPATRICK FLEMING FLETCHER FLORES FLOWERS FLOYD FLYNN FOLEY
FORBES FORD FOREMAN FOSTER FOWLER FOX FRANCIS FRANCO FRANK FRANKLIN FRANKS FRAZIER FREEMAN
FRENCH FROST FRY FRYE FUENTES FULLER FULTON GAINES GALLAGHER GALLEGOS GALLOWAY GAMBLE GARCIA
GARDNER GARNER GARRETT GARRISON GARZA GATES GAY GENTRY GEORGE GIBBS GIBSON GILBERT GILES GILL
GILLESPIE GILLIAM GILMORE GLASS GLENN GLOVER GOFF GOLDEN GOMEZ GONZALES GONZALEZ GOOD GOODMAN
GOODWIN GORDON GOULD GRAHAM GRANT GRAVES GRAY GREEN GREENE GREER GREGORY GRIFFIN GRIFFITH
GRIMES GROSS GUERRA GUERRERO GUTHRIE GUTIERREZ GUY GUZMAN HAHN HALE HALEY HALL HAMILTON
HAMMOND HAMPTON HANCOCK HANEY HANSEN HANSON HARDIN HARDING HARDY HARMON HARPER HARRELL
HARRINGTON HARRIS HARRISON HART HARVEY HATFIELD HAWKINS HAYDEN HAYES HAYNES HAYS HEAD HEATH
HEBERT HENDERSON HENDRICKS HENDRIX HENRY HENSLEY HENSON HERMAN HERNANDEZ HERRERA HERRING
HESS HESTER HEWITT HICKMAN HICKS HIGGINS HILL HINES HINTON HOBBS HODGE HODGES HOFFMAN HOGAN
HOLCOMB HOLDEN HOLDER HOLLAND HOLLOWAY HOLMAN HOLMES HOLT HOOD HOOPER HOOVER HOPKINS HOPPER
HORN HORNE HORTON HOUSE HOUSTON HOWARD HOWE HOWELL HUBBARD HUBER HUDSON HUFF HUFFMAN HUGHES
HULL HUMPHREY HUNT HUNTER HURLEY HURST HUTCHINSON HYDE INGRAM IRWIN JACKSON JACOBS JACOBSON
JAMES JARVIS JEFFERSON JENKINS JENNINGS JENSEN JIMENEZ JOHNS JOHNSON JOHNSTON JONES JORDAN
JOSEPH JOYCE JOYNER JUAREZ JUSTICE KANE KAUFMAN KEITH KELLER KELLEY KELLY KEMP KENNEDY KENT
KERR KEY KIDD KIM KING KINNEY KIRBY KIRK KIRKLAND KLEIN KLINE KNAPP KNIGHT KNOWLES KNOX KOCH
KRAMER LAMB LAMBERT LANCASTER LANDRY LANE LANG LANGLEY LARA LARSEN LARSON LAWRENCE LAWSON
LE LEACH LEBLANC LEE LEON LEONARD LESTER LEVINE LEVY LEWIS LINDSAY LINDSEY LITTLE LIVINGSTON
LLOYD LOGAN LONG LOPEZ LOTT LOVE LOWE LOWERY LUCAS LUNA LYNCH LYNN LYONS MACDONALD MACIAS
MACK MADDEN MADDOX MALDONADO MALONE MANN MANNING MARKS MARQUEZ MARSH MARSHALL MARTIN
MARTINEZ MASON MASSEY MATHEWS MATHIS MATTHEWS MAXWELL MAY MAYER MAYNARD MAYO MAYS MCBRIDE
MCCALL MCCARTHY MCCARTY MCCLAIN MCCLURE MCCONNELL MCCORMICK MCCOY MCCULLOUGH MCDANIEL
MCDONALD MCDOWELL MCFADDEN MCFARLAND MCGEE MCGOWAN MCGUIRE MCINTOSH MCINTYRE MCKAY MCKEE
MCKENZIE MCKINNEY MCKNIGHT MCLAUGHLIN MCLEAN MCLEOD MCMAHON MCMILLAN MCNEIL MCPHERSON MEADOWS
MEDINA MEJIA MELENDEZ MELTON MENDEZ MENDOZA MERCADO MERCER MERRILL MERRITT MEYER MEYERS
MICHAEL MIDDLETON MILES MILLER MILLS MIRANDA MITCHELL MOLINA MONROE MONTGOMERY MONTOYA MOODY
MOON MOONEY MOORE MORALES MORAN MORENO MORGAN MORIN MORRIS MORRISON MORROW MORSE MORTON
MOSES MOSLEY MOSS MUELLER MULLEN MULLINS MUNOZ MURPHY MURRAY MYERS NASH NAVARRO NEAL NELSON
NEWMAN NEWTON NGUYEN NICHOLS NICHOLSON NIELSEN NIEVES NIXON NOBLE NOEL NOLAN NORMAN NORRIS
NORTON NUNEZ OBRIEN OCHOA OCONNOR ODOM ODONNELL OLIVER OLSEN OLSON ONEAL ONEIL ONEILL ORR
ORTEGA ORTIZ OSBORN OSBORNE OWEN OWENS PACE PACHECO PADILLA PAGE PALMER PARK PARKER PARKS
PARRISH PARSONS PATE PATEL PATRICK PATTERSON PATTON PAUL PAYNE PEARSON PECK PENA PENNINGTON
PERez PERKINS PERRY PETERS PETERSEN PETERSON PETTY PHELPS PHILLIPS PICKETT PIERCE PITTMAN
PITTS POLLARD POOLE POPE PORTER POTTER POTTS POWELL POWERS PRATT PRESTON PRICE PRINCE PRUITT
PUCKETT PUGH QUINN RAMIREZ RAMOS RAMSEY RANDALL RANDOLPH RASMUSSEN RATLIFF RAY RAYMOND REED
REESE REEVES REID REILLY REYES REYNOLDS RHODES RICE RICH RICHARD RICHARDS RICHARDSON RICHMOND
RIDDLE RIGGS RILEY RIOS RIVAS RIVERA RIVERS ROACH ROBBINS ROBERSON ROBERTS ROBERTSON ROBINSON
ROBLES ROCHA RODGERS RODRIGUEZ ROGERS ROJAS ROLLINS ROMAN ROMERO ROSA ROSALES ROSE ROSS ROTH
ROWE ROWLAND ROY RUIZ RUSH RUSSELL RUSSO RUTLEDGE RYAN SALAS SALAZAR SALINAS SAMPSON SANCHEZ
SANDERS SANDOVAL SANFORD SANTANA SANTIAGO SANTOS SARGENT SAUNDERS SAVAGE SAWYER SCHMIDT
SCHNEIDER SCHROEDER SCHULTZ SCHWARTZ SCOTT SEARS SELLERS SERRANO SEXTON SHAFFER SHANNON
SHARP SHARPE SHAW SHEPARD SHEPHERD SHEPPARD SHERMAN SHIELDS SHORT SILVA SIMMONS SIMON
SIMPSON SIMS SINGLETON SKINNER SLATER SLOAN SMALL SMITH SNIDER SNOW SNYDER SOLIS SOLOMON
SOSA SOTO SPARKS SPEARS SPENCE SPENCER STAFFORD STANLEY STANTON STARK STEELE STEIN STEPHENS
STEPHENSON STEVENS STEVENSON STEWART STOKES STONE STOUT STRICKLAND STRONG STUART SUAREZ
SULLIVAN SUMMERS SUTTON SWANSON SWEENEY SWEET SYKES TALLEY TANNER TATE TAYLOR TERRELL TERRY
THOMAS THOMPSON THORNTON TILLMAN TODD TORRES TOWNSEND TRAN TRAVIS TREVINO TRUJILLO TUCKER
TURNER TYLER TYSON UNDERWOOD VALDEZ VALENCIA VALENTINE VALENZUELA VANCE VARGAS VASQUEZ
VAUGHAN VAUGHN VAZQUEZ VEGA VELASQUEZ VELAZQUEZ VELEZ VILLARREAL VINCENT VINSON WADE WAGNER
WALKER WALL WALLACE WALLER WALLS WALSH WALTER WALTERS WALTON WARD WARE WARNER WARREN
WASHINGTON WATERS WATKINS WATSON WATTS WEAVER WEBB WEBER WEBSTER WEEKS WEISS WELCH WELLS WEST
WHEELER WHITAKER WHITE WHITEHEAD WHITFIELD WHITLEY WHITNEY WIGGINS WILCOX WILDER WILEY
WILKERSON WILKINS WILKINSON WILLIAM WILLIAMS WILLIAMSON WILLIS WILSON WINTERS WISE WITT
WOLF WOLFE WONG WOOD WOODARD WOODS WOODWARD WOOTEN WORKMAN WRIGHT WYATT WYNN YANG YATES YORK
YOUNG ZAMORA ZIMMERMAN
""".upper().split()

STREET_NAMES = """
MAPLE OAK CEDAR ELM WALNUT BIRCH PINE WILLOW CHESTNUT SYCAMORE HICKORY SPRUCE ASH LOCUST
POPLAR MAGNOLIA LAUREL HAWTHORN JUNIPER ALDER CYPRESS DOGWOOD HAZEL HOLLY LINDEN MULBERRY
PECAN REDWOOD SEQUOIA TAMARACK RIVER LAKE HILL VALLEY MEADOW RIDGE PARK FOREST GARDEN
ORCHARD PRAIRIE SUMMIT HARBOR BRIDGE MILL CHURCH SCHOOL MARKET UNION LIBERTY CENTER CENTRAL
MAIN HIGH BROAD FRONT WATER SPRING CREEK BROOK GLEN GROVE HEIGHTS HIGHLAND HILLSIDE LAKEVIEW
LAKEWOOD MEADOWBROOK MOUNTAIN NORTH SOUTH EAST WEST SUNSET SUNRISE SUNNYSIDE WOODLAND
WASHINGTON JEFFERSON LINCOLN MADISON MONROE JACKSON FRANKLIN HARRISON GRANT SHERMAN ADAMS
CLEVELAND COLUMBUS DOUGLAS FULTON GARFIELD HAMILTON HANCOCK LAFAYETTE LEXINGTON MARSHALL
PERSHING PIERCE POLK SHERIDAN TAYLOR TYLER WARREN WAYNE WEBSTER
""".split()
STREET_SUFFIXES = ["ST", "AVE", "RD", "DR", "LN", "CT", "BLVD", "WAY", "PL", "TRL", "CIR", "TER"]
UNIT_TYPES = ["APT", "UNIT", "STE", "LOT", "#", "BLDG"]

# fictional-sounding place names so a fake city is never mistaken for the real one
CITIES = [c.replace("-", " ") for c in """
ALDERBROOK AMBERFIELD ASHFORD ASHGROVE BARLOWE BAYVIEW BEACONSFIELD BELLHAVEN BIRCHWOOD
BLACKMOOR BRAMBLEWOOD BRIARWOOD BRIGHTWATER BROOKHAVEN CALDERWOOD CASTLEBROOK CEDARVILLE
CLEARWATER CLIFFHAVEN COLDBROOK COPPERFIELD CRESTWOOD CROSSHAVEN DEERFIELD DUNMORE EASTON
EDGEWATER ELMHURST EMBERLY FAIRMONT FALLBROOK FERNDALE FOXHOLLOW GLENWOOD GOLDENVALE
GRANITE-FALLS GREENFIELD GREYSTONE HARTLAND HAVENBROOK HAWTHORNE HILLCREST HOLLOWAY
IRONWOOD IVYBRIDGE JASPER-CREEK KINGSFORD KINGSTON LAKESIDE LARKSPUR LINWOOD LONGMEADOW
MAPLEWOOD MARLOWE MEADOWVALE MILLBROOK MISTHAVEN MOORFIELD NORTHFIELD OAKRIDGE OLDBRIDGE
PEBBLE-CREEK PINEHURST QUARRYTON RAVENSWOOD REDFORD RIVERTON ROCKFORD ROSEDALE SADDLEBROOK
SHADY-GROVE SILVERTON SPRINGDALE STONEBRIDGE STONEHAVEN SUMMERVILLE TANGLEWOOD THORNBURY
TIMBERLAKE VALEWOOD WESTFIELD WHITFIELD WILLOWBROOK WINDSOR WINTERHAVEN WOODLAND WYNDHAM
""".split()]

FIRST_NAMES, LAST_NAMES = list(dict.fromkeys(FIRST_NAMES)), list(dict.fromkeys(LAST_NAMES))
ORG_WORDS = ["SUMMIT", "HARBOR", "PIONEER", "KEYSTONE", "BEACON", "NORTHSTAR", "EVERGREEN",
             "CORNERSTONE", "HERITAGE", "HORIZON", "LIBERTY", "MERIDIAN"]
ORG_SUFFIX = ["GROUP", "SERVICES", "PARTNERS", "ASSOCIATES", "ENTERPRISES", "LLC", "INC"]

# HHS de-identification guidance, Safe Harbor §3.3: 3-digit ZIP areas with < 20,000
# people (2000 Census list published by OCR).  OCR says not to rely on this list if a
# newer one has been published — check hhs.gov before relying on it.
RESTRICTED_ZIP3 = {"036", "059", "063", "102", "203", "556", "692", "790", "821", "823",
                   "830", "831", "878", "879", "884", "890", "893"}

# --------------------------------------------------------------------------------------
# Segment / qualifier policy
# --------------------------------------------------------------------------------------
PATIENT_ENTITIES = {"IL", "QC"}
ADDRESS_ENTITIES = {"IL", "QC", "PW", "45"}       # PW/45 = ambulance pick-up / drop-off
ADDRESS_ENTITIES_IF_NO_NPI = {"77"}               # service facility w/o NPI = patient's home
PROVIDER_ENTITIES = {"82", "71", "72", "77", "DN", "DK", "DQ", "P3", "QB", "QD", "QV", "ZZ",
                     "PW", "45", "FA", "SJ", "73", "DD"}
REF_ALWAYS = {"EA", "SY", "1W", "23", "IG"}      # MRN, SSN, member/client/policy numbers
REF_CLAIM_IDS = {"6R", "G1", "9F", "F8", "D9"}   # line ctrl, prior auth, referral, payer
                                                  # claim ctrl, clearinghouse trace
DATE_FORMATS = {"D8", "RD8", "DT", "D6"}
TIME_FORMATS = {"TM"}


class Policy:
    """Which transformations are on.  Built from the CLI options.

    basic        patient identity only (name / address / DOB / member ID / MRN / SSN /
                 contact info / relatives named in NTE).  Fine-grained opt-ins add more.
    expert       the transformations an Expert Determination (164.514(b)(1)) typically
                 relies on, keeping as much of the claim as possible.
    safe-harbor  164.514(b)(2) Safe Harbor.
    """

    def __init__(self, a):
        mode = a.mode
        self.mode = mode
        sh, ex = mode == "safe-harbor", mode == "expert"
        self.safe_harbor = sh
        self.pseudonyms = "random" if sh else "hmac"
        def choose(explicit, mode_default):
            return mode_default if explicit is None else bool(explicit)

        shift = choose(a.shift_service_dates, ex) or (a.date_shift_days is not None
                                                      and a.shift_service_dates is None)
        if sh:
            self.date_mode = "year"
        elif shift:
            self.date_mode = "shift"
        else:
            self.date_mode = "keep"
        self.date_shift_days = max(1, a.date_shift_days or 60)
        self.id_keep_tail = 0 if sh else max(0, a.id_keep_tail)
        self.dob_mode = "year" if sh else "shift"
        self.claim_ids = sh or choose(a.scramble_claim_ids, ex)
        self.provider_names = sh or choose(a.scramble_provider_names, ex)
        if sh:
            self.zip_mode = "zip3"
        elif a.zip_mode is not None:
            self.zip_mode = a.zip_mode
        else:
            self.zip_mode = "zip3" if ex else "keep"
        self.sbr03_always = sh
        self.free_text = "redact" if sh else "scrub"
        self.envelope_dates = sh


# --------------------------------------------------------------------------------------
# Deterministic (or random) value replacement
# --------------------------------------------------------------------------------------
class Scrambler:
    SUFFIXES = {"JR", "JR.", "SR", "SR.", "II", "III", "IV", "V"}

    def __init__(self, seed: str, policy: Policy):
        self.seed = seed.encode("utf-8")
        self.policy = policy
        self.mapping = {}             # (category, real) -> fake
        self.sysrand = random.SystemRandom()

    # -- core: look up or create a fake for (category, real) -----------------------------
    def _fake(self, category, real, make):
        key = (category, real)
        if key in self.mapping:
            return self.mapping[key]
        if self.policy.pseudonyms == "hmac":
            digest = hmac.new(self.seed, f"{category}\x1f{real}".encode("utf-8"),
                              hashlib.sha256).digest()
            rng = random.Random(int.from_bytes(digest, "big"))
        else:
            rng = self.sysrand       # not derived from the value in any way
        fake = make(rng)
        self.mapping[key] = fake
        return fake

    @staticmethod
    def _pick(rng, pool, avoid):
        """rng.choice(pool), but never the real value itself (real names do occur in the
        fake pools)."""
        c = rng.choice(pool)
        if c == avoid:
            c = pool[(pool.index(c) + 1) % len(pool)]
        return c

    @property
    def stats(self):
        out = {}
        for (cat, _real) in self.mapping:
            out[cat] = out.get(cat, 0) + 1
        return out

    # -- same-shape identifiers ------------------------------------------------------------
    def same_shape(self, value: str, category="id") -> str:
        if not value:
            return value

        def make(rng):
            out = []
            for ch in value:
                if ch.isdigit():
                    out.append(str(rng.randrange(10)))
                elif ch.isalpha():
                    c = chr(ord("A") + rng.randrange(26))
                    out.append(c if ch.isupper() else c.lower())
                else:
                    out.append(ch)
            fake = "".join(out)
            if fake == value and any(c.isalnum() for c in value):
                fake = fake[:-1] + ("0" if fake[-1] != "0" else "1")
            return fake
        return self._fake(category, value, make)

    def member_id(self, value: str) -> str:
        """Member IDs sometimes carry a plan suffix ("1234/CHOICE"); map the core so the
        same person keeps the same fake ID with or without the suffix."""
        if not value:
            return value
        core, sep, rest = value.partition("/")
        k = self.policy.id_keep_tail
        if k and len(core) > k + 2:          # keep a payer-format tail such as IHCP's "99"
            return self.same_shape(core[:-k], "member_id") + core[-k:] + sep + rest
        return self.same_shape(core, "member_id") + sep + rest

    def claim_id(self, value: str) -> str:
        """CLM01 patient account numbers are often <office>-<sequence>.  The office prefix
        is not an identifier, so keep it and replace only the unique part."""
        if not value:
            return value
        head, sep, tail = value.partition("-")
        if sep and sum(c.isalnum() for c in tail) >= 4:
            return head + sep + self.same_shape(tail, "claim_id")
        return self.same_shape(value, "claim_id")

    # -- names ---------------------------------------------------------------------------------
    # Names live in two separate tables: "pt" (patient / subscriber / dependent) and
    # "rel" (everyone else: relatives in NTE, aides, contact persons).  A relative who
    # really shares the patient's surname therefore never shares the patient's FAKE
    # surname, and a note can never end up naming the fake patient.
    def last_name(self, real: str, ns: str = "pt") -> str:
        if not real:
            return real
        toks = real.upper().split()
        fake = self._fake(ns + "_last_name", toks[0], lambda r: self._pick(r, LAST_NAMES, toks[0]))
        extra = [t for t in toks[1:] if t in self.SUFFIXES]
        return " ".join([fake] + extra)

    def first_name(self, real: str, ns: str = "pt") -> str:
        if not real:
            return real
        up = real.upper()
        return self._fake(ns + "_first_name", up, lambda r: self._pick(r, FIRST_NAMES, up))

    def middle_name(self, real: str, ns: str = "pt") -> str:
        if not real:
            return real
        up = real.upper()
        if len(real) > 2:
            return self._fake(ns + "_middle_name", up, lambda r: self._pick(r, FIRST_NAMES, up))
        return self._fake(ns + "_middle_name", up,
                          lambda r: self._pick(r, [chr(ord("A") + i) for i in range(26)], up))

    def freeform_name(self, real: str, ns: str = "rel") -> str:
        toks = real.upper().split()
        if not toks:
            return real
        out = [self.first_name(toks[0], ns)]
        out += [self.middle_name(t, ns) for t in toks[1:-1]]
        if len(toks) > 1:
            out.append(self.last_name(toks[-1], ns))
        return " ".join(out)

    def org_name(self, real: str) -> str:
        if not real:
            return real
        return self._fake("org_name", real.upper(),
                          lambda r: f"{r.choice(ORG_WORDS)} {r.choice(ORG_SUFFIX)}")

    # -- address ---------------------------------------------------------------------------------
    def street(self, real: str) -> str:
        if not real:
            return real
        return self._fake("street", real.upper(), lambda r: (
            f"{r.randrange(100, 9999)} {r.choice(STREET_NAMES)} {r.choice(STREET_SUFFIXES)}"))

    def street2(self, real: str) -> str:
        if not real:
            return real
        return self._fake("street2", real.upper(),
                          lambda r: f"{r.choice(UNIT_TYPES)} {r.randrange(1, 999)}")

    def city(self, real: str) -> str:
        if not real:
            return real
        up = real.upper()
        return self._fake("city", up, lambda r: self._pick(r, CITIES, up))

    def zip_code(self, real: str) -> str:
        mode = self.policy.zip_mode
        if not real or mode == "keep":
            return real
        digits = real.isdigit()
        if mode == "zip3":
            if digits and len(real) >= 5:
                z3 = real[:3]
                return ("000" if z3 in RESTRICTED_ZIP3 else z3) + "00"
            return "00000"

        def make(rng):
            fake = "".join(str(rng.randrange(10)) if c.isdigit() else c for c in real)
            if digits and fake.startswith("0"):
                fake = "1" + fake[1:]
            return fake
        return self._fake("zip", real, make)

    # -- contact ---------------------------------------------------------------------------------
    def contact_value(self, qualifier: str, real: str) -> str:
        if not real:
            return real
        if qualifier == "EM":
            return self._fake("email", real.lower(), lambda r: (
                f"{r.choice(FIRST_NAMES).lower()}.{r.choice(LAST_NAMES).lower()}@example.com"))
        if qualifier == "UR":
            return "https://example.com"
        return self.same_shape(real, "phone")

    # -- dates -------------------------------------------------------------------------------------
    def dob(self, real: str, person_key: str, as_of: date) -> str:
        d = _parse_d8(real)
        if d is None:
            return real
        if self.policy.dob_mode == "year":
            age_years = (as_of - d).days / 365.25
            year = as_of.year - 90 if age_years > 89 else d.year
            return f"{year:04d}0101"

        def make(rng):
            delta = rng.randrange(1, 731) * rng.choice((-1, 1))
            fake = d + timedelta(days=delta)
            if fake > as_of:
                fake = d - timedelta(days=abs(delta))
            if (as_of - fake).days > 89 * 365.25:
                fake = as_of - timedelta(days=int(89 * 365.25) - rng.randrange(0, 365))
            return fake.strftime("%Y%m%d")
        return self._fake("dob", f"{person_key}|{real}", make)

    def service_offset_days(self, patient_key: str) -> int:
        if self.policy.date_mode != "shift":
            return 0
        n = self.policy.date_shift_days
        return int(self._fake("svc_offset", patient_key, lambda r: str(-r.randrange(1, n + 1))))

    def transform_date(self, fmt: str, value: str, offset_days: int) -> str:
        """Apply the active date policy to one DTP/HI/PAT value."""
        if not value:
            return value
        mode = self.policy.date_mode
        if mode == "keep":
            return value
        try:
            if mode == "year":
                return _year_only(fmt, value)
            if fmt == "D8" and len(value) == 8:
                return _shift_d8(value, offset_days)
            if fmt == "RD8" and len(value) == 17 and value[8] == "-":
                return _shift_d8(value[:8], offset_days) + "-" + _shift_d8(value[9:], offset_days)
            if fmt == "DT" and len(value) >= 12:
                return _shift_d8(value[:8], offset_days) + value[8:]
            if fmt == "D6" and len(value) == 6:
                return _shift_d8("20" + value, offset_days)[2:]
        except ValueError:
            pass
        return value


def _parse_d8(s: str):
    try:
        return datetime.strptime(s, "%Y%m%d").date()
    except (ValueError, TypeError):
        return None


def _shift_d8(s: str, days: int) -> str:
    d = _parse_d8(s)
    if d is None:
        raise ValueError(s)
    return (d + timedelta(days=days)).strftime("%Y%m%d")


def _year_only(fmt: str, value: str) -> str:
    if fmt == "D8" and len(value) == 8:
        return value[:4] + "0101"
    if fmt == "RD8" and len(value) == 17 and value[8] == "-":
        return value[:4] + "0101-" + value[9:13] + "0101"
    if fmt == "DT" and len(value) >= 12:
        return value[:4] + "0101" + "0" * (len(value) - 8)
    if fmt == "D6" and len(value) == 6:
        return value[:2] + "0101"
    if fmt in TIME_FORMATS:
        return "0" * len(value)
    return value


# --------------------------------------------------------------------------------------
# X12 parsing (delimiter-preserving)
# --------------------------------------------------------------------------------------
class X12Delims:
    def __init__(self, isa: str):
        if not isa.startswith("ISA") or len(isa) < 106:
            raise ValueError("file does not start with a valid 106-character ISA segment")
        self.elem = isa[3]
        self.rep = isa[82]
        self.comp = isa[104]
        self.seg = isa[105]


def split_segments(text: str, seg_term: str):
    """[(leading_whitespace, body), ...], trailing_remainder — lossless."""
    pieces = text.split(seg_term)
    remainder = pieces.pop()
    out = []
    for p in pieces:
        stripped = p.lstrip("\r\n \t")
        out.append((p[: len(p) - len(stripped)], stripped))
    return out, remainder


# --------------------------------------------------------------------------------------
# Core obfuscation of one file
# --------------------------------------------------------------------------------------
class FileObfuscator:
    def __init__(self, scr: Scrambler, policy: Policy):
        self.scr = scr
        self.policy = policy

    def run(self, text: str) -> str:
        d = X12Delims(text[:106])
        segs, remainder = split_segments(text, d.seg)
        E, C = d.elem, d.comp

        # file date (for the age clamp) from the ORIGINAL GS04
        as_of = date.today()
        for _, body in segs:
            if body.startswith("GS" + E):
                as_of = _parse_d8(body.split(E)[4]) or as_of
                break

        # ---- pass 1: names of persons we will replace, and all member IDs --------------
        pt_tokens, rel_tokens, member_ids = {}, {}, set()
        for _, body in segs:
            if not body.startswith("NM1" + E):
                continue
            el = body.split(E) + [""] * 12
            if el[1] in PATIENT_ENTITIES and el[9]:
                member_ids.add(el[9])
                member_ids.add(el[9].partition("/")[0])
            if el[2] == "1" and self._person_is_obfuscated(el):
                ns = "pt" if el[1] in PATIENT_ENTITIES else "rel"
                table = pt_tokens if ns == "pt" else rel_tokens
                for tok in re.split(r"[\s,]+", el[3].upper()):
                    if len(tok) >= 3 and tok.isalpha() and tok not in Scrambler.SUFFIXES:
                        table[tok] = self.scr.last_name(tok, ns)
                for tok in re.split(r"[\s,]+", el[4].upper()):
                    if len(tok) >= 3 and tok.isalpha():
                        table[tok] = self.scr.first_name(tok, ns)

        # ---- pass 2: rewrite --------------------------------------------------------------
        st = {"in_patient": False, "patient_key": "file", "name_key": "file", "dob_set": False,
              "svc_offset": 0, "key_set": False,
              "addr_ctx": False, "as_of": as_of, "comp": C,
              "pt_tokens": pt_tokens, "rel_tokens": rel_tokens, "member_ids": member_ids,
              "patient_fake": ""}
        out = []
        for prefix, body in segs:
            if body:
                el = body.split(E)
                tag = el[0]
                if tag == "HL":
                    level = el[3] if len(el) > 3 else ""
                    if level == "20":
                        st["in_patient"] = False
                    elif level in ("22", "23"):
                        st["in_patient"] = True
                        st["key_set"] = st["dob_set"] = False
                    st["addr_ctx"] = False
                elif tag in ("SE", "GE", "IEA"):
                    st["in_patient"] = st["addr_ctx"] = False
                elif tag in ("ISA", "GS", "BHT"):
                    if self.policy.envelope_dates:
                        el = self.seg_envelope(el)
                else:
                    handler = getattr(self, "seg_" + tag, None) if tag.isalnum() else None
                    if st["in_patient"] and handler is not None:
                        el = handler(el, st)
                    elif st["in_patient"] and tag not in ("N3", "N4", "PER"):
                        st["addr_ctx"] = False
                body = E.join(el)
            out.append(prefix + body + d.seg)
        result = "".join(out) + remainder
        return result, self._leak_check(segs, split_segments(result, d.seg)[0], E)

    def _leak_check(self, orig, new, E):
        """Position-by-position check that every patient element we are responsible for
        actually changed.  Returns a list of (segment_no, description)."""
        problems, in_pat, ctx, n = [], False, False, 0
        year_mode = self.policy.dob_mode == "year"
        for (_, a), (_, b) in zip(orig, new):
            n += 1
            x, y = a.split(E), b.split(E)
            tag = x[0]
            if tag == "HL":
                in_pat = len(x) > 3 and x[3] != "20"
                ctx = False
                continue
            if not in_pat:
                continue
            if tag == "NM1":
                ctx = len(x) > 1 and x[1] in PATIENT_ENTITIES
                if ctx:
                    for i, what in ((3, "last name"), (4, "first name"), (9, "member ID")):
                        if len(x) > i and x[i] and len(y) > i and y[i] == x[i]:
                            problems.append((n, f"NM1 {what} unchanged: {x[i]}"))
            elif tag == "N3" and ctx and len(x) > 1 and x[1] and y[1] == x[1]:
                problems.append((n, f"N3 street unchanged: {x[1]}"))
            elif tag == "N4" and ctx and len(x) > 1 and x[1] and y[1] == x[1]:
                problems.append((n, f"N4 city unchanged: {x[1]}"))
            elif tag == "DMG" and len(x) > 2 and x[2]:
                if year_mode and not y[2].endswith("0101"):
                    problems.append((n, f"DMG not year-only: {y[2]}"))
                elif not year_mode and y[2] == x[2]:
                    problems.append((n, f"DMG DOB unchanged: {x[2]}"))
            elif tag == "REF" and len(x) > 2 and x[1] in REF_ALWAYS and x[2] and y[2] == x[2]:
                problems.append((n, f"REF {x[1]} unchanged: {x[2]}"))
        return problems

    # -- helpers ---------------------------------------------------------------------------------
    def _person_is_obfuscated(self, el) -> bool:
        if el[1] in PATIENT_ENTITIES:
            return True
        return self.policy.provider_names and el[2] == "1" and el[8] != "XX"

    @staticmethod
    def _trim(el, keep=1):
        """Drop trailing empties we added by padding, but never below the original
        element count, so a segment that already had trailing separators is unchanged."""
        while len(el) > keep and el[-1] == "":
            el.pop()
        return el

    # -- envelope (safe-harbor only) ----------------------------------------------------------
    def seg_envelope(self, el):
        tag = el[0]
        if tag == "ISA" and len(el) > 10:
            el[9] = el[9][:2] + "0101" if len(el[9]) == 6 else el[9]     # YYMMDD
            el[10] = "0" * len(el[10])                                   # HHMM
        elif tag in ("GS", "BHT") and len(el) > 5:
            if len(el[4]) == 8:
                el[4] = el[4][:4] + "0101"
            el[5] = "0" * len(el[5])
        return el

    # -- segment handlers -----------------------------------------------------------------------
    def seg_NM1(self, el, st):
        n_orig = len(el)
        el += [""] * (12 - len(el))
        ent, etype = el[1], el[2]
        orig_last, orig_first, orig_id = el[3], el[4], el[9]
        obf = self._person_is_obfuscated(el)
        if obf:
            ns = "pt" if ent in PATIENT_ENTITIES else "rel"
            if etype == "1":
                el[3] = self.scr.last_name(el[3], ns)
                el[4] = self.scr.first_name(el[4], ns)
                el[5] = self.scr.middle_name(el[5], ns)
            else:
                el[3] = self.scr.org_name(el[3])
            if ent in PATIENT_ENTITIES:
                if el[9]:
                    el[9] = self.scr.member_id(el[9])
                st["patient_fake"] = f"{el[4]} {el[3]}".strip()
        if ent in PATIENT_ENTITIES and (not st["key_set"] or ent == "QC"):
            # person key = name (+ DOB once the DMG arrives); NOT the member ID, so the
            # same person billed to two payers gets the same fake DOB and date offset
            st["name_key"] = f"{orig_last}|{orig_first}".upper()
            st["patient_key"] = st["name_key"]
            st["svc_offset"] = self.scr.service_offset_days(st["patient_key"])
            st["key_set"] = True
            st["dob_set"] = False
        st["addr_ctx"] = (ent in ADDRESS_ENTITIES
                          or (ent in ADDRESS_ENTITIES_IF_NO_NPI and el[8] != "XX")
                          or (obf and ent not in PROVIDER_ENTITIES))
        return self._trim(el, n_orig)

    def seg_N3(self, el, st):
        if st["addr_ctx"]:
            if len(el) > 1:
                el[1] = self.scr.street(el[1])
            if len(el) > 2:
                el[2] = self.scr.street2(el[2])
        return el

    def seg_N4(self, el, st):
        if st["addr_ctx"]:
            if len(el) > 1:
                el[1] = self.scr.city(el[1])
            if len(el) > 3:
                el[3] = self.scr.zip_code(el[3])
            if len(el) > 6 and el[6]:          # county code: smaller than a state
                el[5] = el[6] = ""
                el = self._trim(el, 4)
        return el

    def seg_PER(self, el, st):
        if st["addr_ctx"]:
            if len(el) > 2 and el[2]:
                el[2] = self.scr.freeform_name(el[2])
            for q, v in ((3, 4), (5, 6), (7, 8)):
                if len(el) > v and el[q]:
                    el[v] = self.scr.contact_value(el[q], el[v])
        return el

    def seg_DMG(self, el, st):
        if len(el) > 2 and el[1] == "D8" and el[2]:
            real = el[2]
            el[2] = self.scr.dob(real, st["name_key"], st["as_of"])
            if not st.get("dob_set"):                 # first DMG of this HL (2010BA/CA)
                st["patient_key"] = f"{st['name_key']}|{real}"
                st["svc_offset"] = self.scr.service_offset_days(st["patient_key"])
                st["dob_set"] = True
        return el

    def seg_PAT(self, el, st):
        for i in range(1, len(el) - 1):
            if el[i] in DATE_FORMATS and el[i + 1]:
                el[i + 1] = self.scr.transform_date(el[i], el[i + 1], st["svc_offset"])
        return el

    def seg_DTP(self, el, st):
        if len(el) > 3 and el[3]:
            if el[2] in DATE_FORMATS:
                el[3] = self.scr.transform_date(el[2], el[3], st["svc_offset"])
            elif el[2] in TIME_FORMATS and self.policy.date_mode == "year":
                el[3] = _year_only(el[2], el[3])
        return el

    def seg_HI(self, el, st):
        if self.policy.date_mode == "keep":
            return el
        C = st["comp"]
        for i in range(1, len(el)):
            comps = el[i].split(C)
            for j in range(len(comps) - 1):
                if comps[j] in DATE_FORMATS and comps[j + 1]:
                    comps[j + 1] = self.scr.transform_date(comps[j], comps[j + 1],
                                                           st["svc_offset"])
            el[i] = C.join(comps)
        return el

    def seg_SBR(self, el, st):
        # SBR03 is the group/policy number, but some payers' files repeat the member ID
        # there.  Replace it with the SAME fake the NM109 gets.
        if len(el) > 3 and el[3] and (self.policy.sbr03_always or el[3] in st["member_ids"]):
            el[3] = self.scr.member_id(el[3])
        return el

    def seg_CLM(self, el, st):
        if len(el) > 1 and el[1] and self.policy.claim_ids:
            el[1] = self.scr.claim_id(el[1])
        return el

    def seg_PWK(self, el, st):
        # PWK06 attachment control number: a unique number tied to this claim
        if len(el) > 6 and el[6] and self.policy.claim_ids:
            el[6] = self.scr.same_shape(el[6], "attachment_ctrl")
        return el

    def seg_REF(self, el, st):
        if len(el) > 2 and el[2]:
            q = el[1]
            if q in REF_ALWAYS or (q in REF_CLAIM_IDS and self.policy.claim_ids):
                el[2] = self.scr.same_shape(el[2], "ref_" + q)
        return el

    def seg_NTE(self, el, st):
        if len(el) > 2 and el[2]:
            el[2] = self._free_text(el[2], st)
        return el

    def seg_K3(self, el, st):
        if len(el) > 1 and el[1]:
            el[1] = self._free_text(el[1], st)
        return el

    # -- free text -------------------------------------------------------------------------------
    def _free_text(self, text: str, st) -> str:
        if self.policy.free_text == "redact":
            return "REDACTED"
        pt_tokens, rel_tokens = st["pt_tokens"], st["rel_tokens"]

        # "NAME: JOHN Q PUBLIC REL: SPOUSE" spans: every token inside is a relative's name
        # and is always drawn from the "rel" table, never the patient's.
        spans = [(m.start(1), m.end(1))
                 for m in re.finditer(r"\bNAME\s*:?\s*(.+?)(?=\s+REL\b)", text, flags=re.I)]

        def _tok(m):
            tok, up = m.group(0), m.group(0).upper()
            span = next(((s, e) for s, e in spans if s <= m.start() < e), None)
            if span is None:
                return rel_tokens.get(up, pt_tokens.get(up, tok))
            if up in ("REL", "NAME"):
                return tok
            if up in rel_tokens:
                return rel_tokens[up]
            if len(up) == 1:
                return self.scr.middle_name(up, "rel")
            return (self.scr.first_name(up, "rel") if m.start() == span[0]
                    else self.scr.last_name(up, "rel"))

        text = re.sub(r"\b[A-Za-z]+\b", _tok, text)
        text = re.sub(r"\d{5,}", lambda m: self.scr.same_shape(m.group(0), "nte_number"), text)

        # belt and braces: a note must never contain the fake patient's full name
        pf = st.get("patient_fake", "")
        if pf and pf in text.upper():
            first, _, rest = pf.partition(" ")
            alt = FIRST_NAMES[(FIRST_NAMES.index(first) + 1) % len(FIRST_NAMES)] \
                if first in FIRST_NAMES else "A"
            text = re.sub(re.escape(pf), f"{alt} {rest}".strip(), text, flags=re.I)
        return text


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def collect_inputs(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    files.append((p, os.path.join(root, n)))
        elif os.path.isfile(p):
            files.append((os.path.dirname(p) or ".", p))
        else:
            print(f"warning: {p} not found, skipped", file=sys.stderr)
    return files


HELP_EPILOG = """\
modes:
  basic        (default) Replace the patient's identity and nothing else.  Service
               dates, claim numbers, provider names and ZIPs stay, so the file
               behaves the same in a test system.  Add any fine-tuning option.
  expert       basic + the fine-tuning options switched on: the usual input for
               an Expert Determination (45 CFR 164.514(b)(1)).  The --seed is
               the hash key; keep it secret.  Not de-identified until an expert
               signs off.
  safe-harbor  HIPAA Safe Harbor, 45 CFR 164.514(b)(2), applied literally.
               Fine-tuning options are ignored.  You must still have no actual
               knowledge that what remains could identify someone.

what each mode changes:
                               basic           expert           safe-harbor
  patient / subscriber names   fake            fake             fake
  member ID, MRN, SSN          pseudonym       pseudonym        random
  street, city, county         fake / dropped  fake / dropped   fake / dropped
  state                        kept            kept             kept
  ZIP                          kept            first 3 digits   first 3 digits*
  date of birth                shifted +-2 yr  shifted +-2 yr   year, 90+ cap
  service / admit / stmt dates kept            shifted 1..N d   year only
  envelope dates (ISA/GS/BHT)  kept            kept             year only
  CLM01, line/auth/trace/PWK # kept            pseudonym **     random
  NPI-less person providers    kept            fake             fake
  NTE / K3 free text           names scrubbed  names scrubbed   REDACTED
  group number (SBR03)         kept ***        kept ***         random
  gender, dx/px codes, charges, NPIs, provider orgs, payers: kept in every mode

    *  000 for the HHS restricted 3-digit areas (< 20,000 people)
    ** office prefix before the hyphen is kept, e.g. 37-104625 -> 37-684996
    *** replaced only when it repeats the member ID

  pseudonym  keyed hash of the real value: same input gives the same output in
             every file, and in every run that uses the same --seed.
  random     not derived from the value at all; reproducible only by reloading
             the table written with --map.

  The same real patient gets the same fake identity everywhere in a run.
  Relatives, aides and contact persons draw from a separate name pool, so they
  never share the patient's fake name.

no arguments at all (e.g. double-clicking the file) opens a window with the same
choices.  Dropping a file or folder onto the .py icon opens the window pre-filled.

exit status:
  0 done   1 nothing written   2 the built-in leak check found a patient element
  that survived unchanged (details on stderr)

examples:
  %(prog)s ./837_files -o ./scrubbed
  %(prog)s ./837_files -o ./scrubbed --id-keep-tail 2 --seed "secret"
  %(prog)s ./837_files -o ./test --shift-service-dates --scramble-claim-ids
  %(prog)s ./837_files -o ./expert --mode expert --seed "my secret"
  %(prog)s ./837_files -o ./deid --mode safe-harbor --map key.csv
  %(prog)s claim.dat --in-place --suffix _scrubbed
"""


def _say(*args, **kw):
    """print() that keeps the run going if stdout is a closed pipe (| head)."""
    try:
        print(*args, **kw)
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="obfuscate_837.py",
        usage="%(prog)s INPUT [INPUT ...] (-o OUTDIR | --in-place) [options]",
        description="Obfuscate PHI in X12 837P / 837I claim files.\n"
                    "Only PHI is touched.  Everything else (envelope, providers, payers,\n"
                    "NPIs, codes, charges, delimiters, line endings, segment counts) is\n"
                    "left byte-for-byte as it was, and every replacement keeps the\n"
                    "original length and pattern so the files still validate.",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", metavar="INPUT", nargs="+",
                    help="837 file, or a directory to walk recursively (non-X12 files are "
                         "skipped)")

    out = ap.add_argument_group("output")
    x = out.add_mutually_exclusive_group()
    x.add_argument("-o", "--out", metavar="OUTDIR",
                   help="write results under OUTDIR, keeping the input folder layout")
    x.add_argument("--in-place", action="store_true",
                   help="overwrite the input files (or, with --suffix, write beside them)")
    out.add_argument("--suffix", metavar="SFX", default="",
                     help="insert SFX before the file extension, e.g. _scrubbed")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="print only warnings and errors")

    m = ap.add_argument_group("mode")
    m.add_argument("--mode", choices=["basic", "expert", "safe-harbor"], default="basic",
                   metavar="basic|expert|safe-harbor",
                   help="how much to change (default basic); see the table below")
    m.add_argument("--seed", metavar="SECRET",
                   help="key for the pseudonym hash (basic and expert).  Same seed, same "
                        "fakes.  Default: a random key, printed so the run can be repeated")

    o = ap.add_argument_group("fine-tuning (expert turns the first three on; safe-harbor "
                              "ignores all of them)")
    o.add_argument("--shift-service-dates", action="store_true", default=None,
                   help="shift every service, admission, statement and other claim date "
                        "back 1..N days, one offset per patient")
    o.add_argument("--scramble-claim-ids", action="store_true", default=None,
                   help="replace CLM01 account numbers, line control, prior-auth, referral, "
                        "payer claim control, trace and attachment numbers")
    o.add_argument("--scramble-provider-names", action="store_true", default=None,
                   help="rename person providers that have no NPI (aides, family "
                        "caregivers); providers with an NPI are never changed")
    o.add_argument("--date-shift-days", type=int, default=None, metavar="N",
                   help="window for the date shift (default 60); implies "
                        "--shift-service-dates")
    o.add_argument("--zip-mode", choices=["keep", "zip3", "random"], default=None,
                   metavar="keep|zip3|random",
                   help="patient ZIP: keep as is (basic default), first 3 digits + 00 "
                        "(expert default), or new random digits")
    o.add_argument("--id-keep-tail", type=int, default=0, metavar="N",
                   help="keep the last N characters of member IDs, for payer formats with a "
                        "fixed tail (Indiana Medicaid RIDs end in 99: use 2)")

    r = ap.add_argument_group("mapping")
    r.add_argument("--map", metavar="CSV",
                   help="write the real -> fake table.  It contains PHI; in safe-harbor mode "
                        "it is the only way back, i.e. the re-identification key")
    r.add_argument("--map-in", metavar="CSV",
                   help="load a table written by --map so this run reuses the same fakes")
    a = ap.parse_args(argv)

    if not a.out and not a.in_place:
        ap.error("choose an output: -o OUTDIR or --in-place")

    def log(msg, level="info"):
        if level == "error" or level == "warn":
            print(msg, file=sys.stderr)
        elif not a.quiet or level == "important":
            _say(msg)

    r = run_job(a, log)
    return 2 if r["leaks"] else (0 if r["done"] else 1)


# --------------------------------------------------------------------------------------
# Shared job runner (CLI and GUI)
# --------------------------------------------------------------------------------------
class Options(argparse.Namespace):
    """Plain holder for the same fields the CLI produces; the GUI fills one of these."""

    def __init__(self, **kw):
        defaults = dict(inputs=[], out=None, in_place=False, suffix="", quiet=False,
                        mode="basic", seed=None, shift_service_dates=None,
                        date_shift_days=None, scramble_claim_ids=None,
                        scramble_provider_names=None, zip_mode=None, id_keep_tail=0,
                        map=None, map_in=None)
        defaults.update(kw)
        super().__init__(**defaults)


def run_job(a, log, progress=None):
    """Run one obfuscation job.  `a` is an argparse Namespace / Options; `log(msg, level)`
    receives every line of output (level: info | important | warn | error);
    `progress(i, n)` is called per file.  Returns a summary dict."""
    policy = Policy(a)
    if policy.safe_harbor:
        ignored = [f for f, v in (("--seed", a.seed), ("--shift-service-dates", a.shift_service_dates),
                                  ("--date-shift-days", a.date_shift_days is not None),
                                  ("--scramble-claim-ids", a.scramble_claim_ids),
                                  ("--scramble-provider-names", a.scramble_provider_names),
                                  ("--zip-mode", a.zip_mode is not None),
                                  ("--id-keep-tail", a.id_keep_tail)) if v]
        if ignored:
            log("--mode safe-harbor: ignoring " + ", ".join(ignored))
        seed = ""
    else:
        seed = a.seed if a.seed is not None else secrets.token_hex(16)
        if a.seed is None:
            log(f"seed (pass --seed to reproduce this mapping): {seed}", "important")

    scr = Scrambler(seed, policy)
    if a.map_in:
        with open(a.map_in, newline="") as fh:
            for row in csv.DictReader(fh):
                scr.mapping[(row["category"], row["real"])] = row["fake"]
    fo = FileObfuscator(scr, policy)

    files = collect_inputs(a.inputs)
    done = skipped = leaks = 0
    for i, (base, path) in enumerate(files, 1):
        if progress:
            progress(i, len(files))
        with open(path, "rb") as fh:
            raw = fh.read()
        if raw[:3] != b"ISA" or len(raw) < 106:
            log(f"skip (not X12): {path}")
            skipped += 1
            continue
        try:
            result, problems = fo.run(raw.decode("latin-1"))
        except Exception as exc:
            log(f"ERROR {path}: {exc}", "error")
            skipped += 1
            continue

        if a.in_place:
            dest = path
        else:
            rel = os.path.relpath(path, base) if os.path.isdir(base) else os.path.basename(path)
            dest = os.path.join(a.out, rel)
        if a.suffix:
            stem, ext = os.path.splitext(dest)
            dest = stem + a.suffix + ext
        if not a.in_place and os.path.abspath(dest) == os.path.abspath(path):
            log(f"ERROR {path}: output would overwrite the input (use --in-place or a "
                f"different -o)", "error")
            skipped += 1
            continue
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(result.encode("latin-1"))
        done += 1
        if problems:
            leaks += len(problems)
            for seg_no, msg in problems:
                log(f"LEAK CHECK {path} segment {seg_no}: {msg}", "warn")
        log(f"ok  {path} -> {dest}")

    if a.map:
        with open(a.map, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["category", "real", "fake"])
            for (cat, real), fake in sorted(scr.mapping.items()):
                w.writerow([cat, real, fake])
        log(f"mapping written to {a.map}  (contains PHI"
            + (" — this is the re-identification key)" if policy.safe_harbor else ")"),
            "important")

    if leaks:
        log(f"\nWARNING: {leaks} patient element(s) survived unchanged — see LEAK CHECK "
            f"lines above", "warn")
    log(f"\n{done} file(s) written, {skipped} skipped, {leaks} leak-check warnings  "
        f"[mode: {a.mode}]")
    if scr.stats:
        log("distinct values replaced by category:")
        for k in sorted(scr.stats):
            log(f"  {k:12s} {scr.stats[k]}")
    if policy.safe_harbor:
        log("\nSafe Harbor reminder: 164.514(b)(2)(ii) still requires that you have no "
            "actual knowledge the remaining data could identify an individual.")
    return {"done": done, "skipped": skipped, "leaks": leaks, "seed": seed, "files": len(files)}


# --------------------------------------------------------------------------------------
# GUI (opens when the script is started with no arguments, e.g. by double-click)
# --------------------------------------------------------------------------------------
MODE_BLURB = {
    "basic": "Replace the patient's identity only (name, address, DOB, member ID, MRN/SSN, "
             "contact info, relatives in notes).  Service dates, claim numbers, provider "
             "names and ZIPs stay.  Best for test data.",
    "expert": "Basic + shifted dates, scrambled claim/line/auth numbers, renamed NPI-less "
              "providers, 3-digit ZIP.  The usual input for an Expert Determination; the "
              "seed is the hash key, keep it secret.",
    "safe-harbor": "HIPAA Safe Harbor (45 CFR 164.514(b)(2)) applied literally: year-only "
                   "dates, 3-digit ZIP, random IDs, notes redacted.  Options below are "
                   "ignored.",
}


def gui(initial_input=None):
    import threading
    import queue
    import subprocess
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    try:                                   # optional: real drag-and-drop into the window
        from tkinterdnd2 import DND_FILES, TkinterDnD
        root = TkinterDnD.Tk()
        dnd = True
    except Exception:
        root = tk.Tk()
        dnd = False

    root.title("837 PHI Obfuscator")
    root.minsize(720, 640)
    pad = {"padx": 8, "pady": 4}
    for i in range(3):
        root.columnconfigure(i, weight=1 if i == 1 else 0)

    def _clean_drop(data):
        # tkinterdnd2 gives "{C:/path with space} C:/other" style lists
        data = data.strip()
        if data.startswith("{"):
            data = data[1:data.index("}")]
        else:
            data = data.split()[0]
        return data

    # ---- 1. input ---------------------------------------------------------------------
    row = 0
    ttk.Label(root, text="1.  Input  (an 837 file or a folder of them)",
              font=("", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", **pad)
    row += 1
    in_var = tk.StringVar(value=initial_input or "")
    in_entry = ttk.Entry(root, textvariable=in_var)
    in_entry.grid(row=row, column=0, columnspan=2, sticky="ew", **pad)
    fr = ttk.Frame(root)
    fr.grid(row=row, column=2, sticky="e", **pad)
    ttk.Button(fr, text="File…", width=8,
               command=lambda: _pick(in_var, filedialog.askopenfilename)).pack(side="left")
    ttk.Button(fr, text="Folder…", width=8,
               command=lambda: _pick(in_var, filedialog.askdirectory)).pack(side="left", padx=(4, 0))
    row += 1
    in_hint = ttk.Label(root, foreground="#666", wraplength=680, justify="left",
                        text=("Drop a file or folder here, type or paste a path, or browse."
                              if dnd else
                              "Type or paste a path, or browse.  (pip install tkinterdnd2 to "
                              "enable drag-and-drop into this window; dropping a file onto the "
                              ".py icon works without it.)"))
    in_hint.grid(row=row, column=0, columnspan=3, sticky="w", **pad)
    row += 1

    # ---- 2. output --------------------------------------------------------------------
    ttk.Label(root, text="2.  Output folder", font=("", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", **pad)
    row += 1
    out_var = tk.StringVar()
    out_entry = ttk.Entry(root, textvariable=out_var)
    out_entry.grid(row=row, column=0, columnspan=2, sticky="ew", **pad)
    ttk.Button(root, text="Folder…", width=8,
               command=lambda: _pick(out_var, filedialog.askdirectory)).grid(
        row=row, column=2, sticky="e", **pad)
    row += 1
    inplace_var = tk.BooleanVar(value=False)
    suffix_var = tk.StringVar(value="")
    fr = ttk.Frame(root)
    fr.grid(row=row, column=0, columnspan=3, sticky="w", **pad)
    ttk.Checkbutton(fr, text="Overwrite the input files in place (no output folder)",
                    variable=inplace_var, command=lambda: _refresh()).pack(side="left")
    ttk.Label(fr, text="     file-name suffix:").pack(side="left")
    ttk.Entry(fr, textvariable=suffix_var, width=12).pack(side="left")
    row += 1

    def _auto_output(*_):
        src = in_var.get().strip().strip('"')
        if src and not out_var.get().strip():
            base = src.rstrip("/\\")
            if os.path.isfile(base):
                base = os.path.dirname(base)
            out_var.set(base + "_scrubbed")
    in_var.trace_add("write", _auto_output)
    _auto_output()

    # ---- 3. mode ----------------------------------------------------------------------
    ttk.Label(root, text="3.  Mode", font=("", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", **pad)
    row += 1
    mode_var = tk.StringVar(value="basic")
    fr = ttk.Frame(root)
    fr.grid(row=row, column=0, columnspan=3, sticky="w", **pad)
    for m, label in (("basic", "Basic (test data)"), ("expert", "Expert Determination"),
                     ("safe-harbor", "Safe Harbor")):
        ttk.Radiobutton(fr, text=label, value=m, variable=mode_var,
                        command=lambda: _apply_mode()).pack(side="left", padx=(0, 16))
    row += 1
    blurb = ttk.Label(root, text=MODE_BLURB["basic"], wraplength=680, foreground="#444")
    blurb.grid(row=row, column=0, columnspan=3, sticky="w", **pad)
    row += 1

    # ---- 4. options -------------------------------------------------------------------
    ttk.Label(root, text="4.  Options", font=("", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", **pad)
    row += 1
    opts = ttk.Frame(root)
    opts.grid(row=row, column=0, columnspan=3, sticky="ew", **pad)
    opts.columnconfigure(1, weight=1)
    shift_var = tk.BooleanVar()
    claim_var = tk.BooleanVar()
    prov_var = tk.BooleanVar()
    zip_var = tk.StringVar(value="keep")
    days_var = tk.StringVar(value="60")
    tail_var = tk.StringVar(value="0")
    seed_var = tk.StringVar(value="")
    map_var = tk.BooleanVar(value=False)
    widgets = []

    def _opt(r, text, var, help_text):
        cb = ttk.Checkbutton(opts, text=text, variable=var)
        cb.grid(row=r, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(opts, text=help_text, foreground="#666").grid(row=r, column=1, sticky="w")
        widgets.append(cb)

    _opt(0, "Shift service dates", shift_var,
         "all claim dates moved back 1..N days, one offset per patient")
    fr = ttk.Frame(opts)
    fr.grid(row=1, column=0, columnspan=2, sticky="w", padx=24)
    ttk.Label(fr, text="N days:").pack(side="left")
    days_entry = ttk.Entry(fr, textvariable=days_var, width=5)
    days_entry.pack(side="left")
    widgets.append(days_entry)
    _opt(2, "Scramble claim IDs", claim_var,
         "CLM01, line control, prior-auth, referral, payer claim, trace, attachment numbers")
    _opt(3, "Scramble provider names", prov_var,
         "person providers without an NPI (aides, family caregivers)")
    fr = ttk.Frame(opts)
    fr.grid(row=4, column=0, columnspan=2, sticky="w", padx=4, pady=2)
    ttk.Label(fr, text="ZIP:").pack(side="left")
    zip_box = ttk.Combobox(fr, textvariable=zip_var, values=["keep", "zip3", "random"],
                           width=8, state="readonly")
    zip_box.pack(side="left", padx=(4, 16))
    widgets.append(zip_box)
    ttk.Label(fr, text="keep | zip3 = first 3 digits + 00 | random", foreground="#666").pack(side="left")
    fr = ttk.Frame(opts)
    fr.grid(row=5, column=0, columnspan=2, sticky="w", padx=4, pady=2)
    ttk.Label(fr, text="Keep last N chars of member IDs:").pack(side="left")
    tail_entry = ttk.Entry(fr, textvariable=tail_var, width=4)
    tail_entry.pack(side="left", padx=4)
    widgets.append(tail_entry)
    ttk.Label(fr, text="(Indiana Medicaid RIDs end in 99: use 2)", foreground="#666").pack(side="left")
    fr = ttk.Frame(opts)
    fr.grid(row=6, column=0, columnspan=2, sticky="ew", padx=4, pady=2)
    ttk.Label(fr, text="Seed (secret key):").pack(side="left")
    seed_entry = ttk.Entry(fr, textvariable=seed_var, width=36)
    seed_entry.pack(side="left", padx=4)
    widgets.append(seed_entry)
    ttk.Label(fr, text="same seed = same fakes next time; blank = random, shown in the log",
              foreground="#666").pack(side="left")
    map_cb = ttk.Checkbutton(opts, text="Save real→fake mapping CSV next to the output "
                             "(contains PHI; in Safe Harbor it is the re-identification key)",
                             variable=map_var)
    map_cb.grid(row=7, column=0, columnspan=2, sticky="w", padx=4, pady=2)
    row += 1

    # ---- 5. run -----------------------------------------------------------------------
    fr = ttk.Frame(root)
    fr.grid(row=row, column=0, columnspan=3, sticky="ew", **pad)
    run_btn = ttk.Button(fr, text="5.  Run", command=lambda: _run())
    run_btn.pack(side="left")
    open_btn = ttk.Button(fr, text="Open output folder", state="disabled",
                          command=lambda: _open_folder())
    open_btn.pack(side="left", padx=8)
    prog = ttk.Progressbar(fr, mode="determinate")
    prog.pack(side="left", fill="x", expand=True, padx=8)
    row += 1
    log_box = tk.Text(root, height=14, wrap="none", state="disabled",
                      font=("Courier", 9) if sys.platform != "win32" else ("Consolas", 9))
    log_box.grid(row=row, column=0, columnspan=3, sticky="nsew", **pad)
    root.rowconfigure(row, weight=1)
    log_box.tag_config("warn", foreground="#b00")
    log_box.tag_config("important", foreground="#06c")
    sb = ttk.Scrollbar(root, orient="vertical", command=log_box.yview)
    sb.grid(row=row, column=3, sticky="ns")
    log_box.configure(yscrollcommand=sb.set)

    # ---- behaviour --------------------------------------------------------------------
    def _pick(var, dialog):
        v = dialog()
        if v:
            var.set(v)

    def _apply_mode():
        m = mode_var.get()
        blurb.configure(text=MODE_BLURB[m])
        if m == "basic":
            shift_var.set(False); claim_var.set(False); prov_var.set(False); zip_var.set("keep")
        elif m == "expert":
            shift_var.set(True); claim_var.set(True); prov_var.set(True); zip_var.set("zip3")
        state = "disabled" if m == "safe-harbor" else "normal"
        for w in widgets:
            w.configure(state=("readonly" if (w is zip_box and state == "normal") else state))

    def _refresh():
        st = "disabled" if inplace_var.get() else "normal"
        out_entry.configure(state=st)

    def _log(msg, level="info"):
        log_box.configure(state="normal")
        log_box.insert("end", msg + "\n", level if level in ("warn", "important") else ())
        log_box.see("end")
        log_box.configure(state="disabled")

    def _open_folder():
        path = out_var.get().strip() if not inplace_var.get() else in_var.get().strip()
        if os.path.isfile(path):
            path = os.path.dirname(path)
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            messagebox.showerror("Open folder", str(exc))

    def _build_options():
        src = in_var.get().strip().strip('"')
        if not src or not os.path.exists(src):
            raise ValueError("Choose an input file or folder that exists.")
        if not inplace_var.get() and not out_var.get().strip():
            raise ValueError("Choose an output folder, or tick 'overwrite in place'.")
        try:
            days = int(days_var.get() or 60)
            tail = int(tail_var.get() or 0)
        except ValueError:
            raise ValueError("'N days' and 'keep last N chars' must be whole numbers.")
        m = mode_var.get()
        out_dir = None if inplace_var.get() else out_var.get().strip().strip('"')
        map_path = None
        if map_var.get():
            map_path = os.path.join(out_dir or os.path.dirname(src) or ".", "mapping_PHI.csv")
        return Options(inputs=[src], out=out_dir, in_place=inplace_var.get(),
                       suffix=suffix_var.get().strip(), mode=m,
                       seed=(seed_var.get() or None) if m != "safe-harbor" else None,
                       shift_service_dates=shift_var.get() if m != "safe-harbor" else None,
                       date_shift_days=days if (shift_var.get() and m != "safe-harbor") else None,
                       scramble_claim_ids=claim_var.get() if m != "safe-harbor" else None,
                       scramble_provider_names=prov_var.get() if m != "safe-harbor" else None,
                       zip_mode=(zip_var.get() if m != "safe-harbor" else None),
                       id_keep_tail=tail if m != "safe-harbor" else 0,
                       map=map_path)

    q = queue.Queue()

    def _run():
        try:
            o = _build_options()
        except ValueError as exc:
            messagebox.showwarning("Check the form", str(exc))
            return
        if o.in_place and not messagebox.askyesno(
                "Overwrite?", "This will overwrite the original files with obfuscated "
                              "copies.  The originals cannot be recovered.  Continue?"):
            return
        log_box.configure(state="normal"); log_box.delete("1.0", "end"); log_box.configure(state="disabled")
        run_btn.configure(state="disabled")
        open_btn.configure(state="disabled")
        prog.configure(value=0, maximum=1)

        def work():
            try:
                r = run_job(o, lambda m, lvl="info": q.put(("log", m, lvl)),
                            lambda i, n: q.put(("prog", i, n)))
                q.put(("done", r, None))
            except Exception as exc:
                q.put(("log", f"ERROR: {exc}", "warn"))
                q.put(("done", None, None))
        threading.Thread(target=work, daemon=True).start()
        root.after(100, _poll)

    def _poll():
        try:
            while True:
                kind, x, y = q.get_nowait()
                if kind == "log":
                    _log(x, y)
                elif kind == "prog":
                    prog.configure(maximum=y, value=x)
                elif kind == "done":
                    run_btn.configure(state="normal")
                    open_btn.configure(state="normal")
                    if x:
                        prog.configure(value=prog["maximum"])
                        msg = f"{x['done']} file(s) written, {x['skipped']} skipped"
                        if x["leaks"]:
                            messagebox.showwarning("Finished with warnings",
                                                   msg + f"\n{x['leaks']} leak-check warning(s) — see the log.")
                        else:
                            messagebox.showinfo("Finished", msg)
                    return
        except queue.Empty:
            pass
        root.after(100, _poll)

    if dnd:
        for w, var in ((in_entry, in_var), (out_entry, out_var), (in_hint, in_var)):
            w.drop_target_register(DND_FILES)
            w.dnd_bind("<<Drop>>", lambda e, v=var: v.set(_clean_drop(e.data)))

    _apply_mode()
    _refresh()
    in_entry.focus_set()
    root.mainloop()


if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv:
        gui()                                   # double-clicked: open the window
    elif len(argv) == 1 and os.path.exists(argv[0]):
        gui(initial_input=argv[0])              # a file/folder dropped onto the .py icon
    else:
        sys.exit(main(argv))
