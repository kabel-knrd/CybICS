EESchema Schematic File Version 4
LIBS:raspberrypi_zerow_uhat-cache
EELAYER 26 0
EELAYER END
$Descr A4 11693 8268
encoding utf-8
Sheet 1 1
Title "Raspberry Pi Zero (W) uHAT Template Board"
Date "2019-02-28"
Rev "1.0"
Comp ""
Comment1 "This Schematic is licensed under MIT Open Source License."
Comment2 ""
Comment3 ""
Comment4 ""
$EndDescr
$Comp
L Connector_Generic:Conn_02x20_Odd_Even J1
U 1 1 5C77771F
P 5250 2950
F 0 "J1" H 5300 4067 50  0000 C CNN
F 1 "GPIO_CONNECTOR" H 5300 3976 50  0000 C CNN
F 2 "lib:PinSocket_2x20_P2.54mm_Vertical_Centered_Anchor" H 5250 2950 50  0001 C CNN
F 3 "~" H 5250 2950 50  0001 C CNN
	1    5250 2950
	1    0    0    -1  
$EndComp
$Comp
L power:GND #PWR0101
U 1 1 5C777805
P 4850 4100
F 0 "#PWR0101" H 4850 3850 50  0001 C CNN
F 1 "GND" H 4855 3927 50  0001 C CNN
F 2 "" H 4850 4100 50  0001 C CNN
F 3 "" H 4850 4100 50  0001 C CNN
	1    4850 4100
	1    0    0    -1  
$EndComp
$Comp
L power:GND #PWR0102
U 1 1 5C777838
P 5750 4100
F 0 "#PWR0102" H 5750 3850 50  0001 C CNN
F 1 "GND" H 5755 3927 50  0001 C CNN
F 2 "" H 5750 4100 50  0001 C CNN
F 3 "" H 5750 4100 50  0001 C CNN
	1    5750 4100
	1    0    0    -1  
$EndComp
Wire Wire Line
	5050 2450 4850 2450
Wire Wire Line
	4850 2450 4850 3250
Wire Wire Line
	5050 3250 4850 3250
Connection ~ 4850 3250
Wire Wire Line
	4850 3250 4850 3950
Wire Wire Line
	5050 3950 4850 3950
Connection ~ 4850 3950
Wire Wire Line
	4850 3950 4850 4100
Wire Wire Line
	5550 2250 5750 2250
Wire Wire Line
	5750 2250 5750 2650
Wire Wire Line
	5550 2650 5750 2650
Connection ~ 5750 2650
Wire Wire Line
	5750 2650 5750 2950
Wire Wire Line
	5550 2950 5750 2950
Connection ~ 5750 2950
Wire Wire Line
	5550 3450 5750 3450
Wire Wire Line
	5750 2950 5750 3450
Connection ~ 5750 3450
Wire Wire Line
	5750 3450 5750 3650
Wire Wire Line
	5550 3650 5750 3650
Connection ~ 5750 3650
Wire Wire Line
	5750 3650 5750 4100
$Comp
L power:+3.3V #PWR0103
U 1 1 5C777AB0
P 4800 1950
F 0 "#PWR0103" H 4800 1800 50  0001 C CNN
F 1 "+3.3V" H 4815 2123 50  0000 C CNN
F 2 "" H 4800 1950 50  0001 C CNN
F 3 "" H 4800 1950 50  0001 C CNN
	1    4800 1950
	1    0    0    -1  
$EndComp
Wire Wire Line
	4800 2050 4800 1950
Wire Wire Line
	5050 2850 4800 2850
Wire Wire Line
	4800 2850 4800 2050
Connection ~ 4800 2050
$Comp
L power:+5V #PWR0104
U 1 1 5C777E01
P 5850 1950
F 0 "#PWR0104" H 5850 1800 50  0001 C CNN
F 1 "+5V" H 5865 2123 50  0000 C CNN
F 2 "" H 5850 1950 50  0001 C CNN
F 3 "" H 5850 1950 50  0001 C CNN
	1    5850 1950
	1    0    0    -1  
$EndComp
Wire Wire Line
	5550 2050 5850 2050
Wire Wire Line
	5850 2050 5850 1950
Wire Wire Line
	5550 2150 5850 2150
Wire Wire Line
	5850 2150 5850 2050
Connection ~ 5850 2050
$Comp
L power:PWR_FLAG #FLG0101
U 1 1 5C77824A
P 4400 1950
F 0 "#FLG0101" H 4400 2025 50  0001 C CNN
F 1 "PWR_FLAG" H 4400 2124 50  0000 C CNN
F 2 "" H 4400 1950 50  0001 C CNN
F 3 "~" H 4400 1950 50  0001 C CNN
	1    4400 1950
	1    0    0    -1  
$EndComp
$Comp
L power:GND #PWR0105
U 1 1 5C778504
P 4450 4200
F 0 "#PWR0105" H 4450 3950 50  0001 C CNN
F 1 "GND" H 4455 4027 50  0001 C CNN
F 2 "" H 4450 4200 50  0001 C CNN
F 3 "" H 4450 4200 50  0001 C CNN
	1    4450 4200
	1    0    0    -1  
$EndComp
$Comp
L power:PWR_FLAG #FLG0102
U 1 1 5C778511
P 4450 4150
F 0 "#FLG0102" H 4450 4225 50  0001 C CNN
F 1 "PWR_FLAG" H 4450 4324 50  0000 C CNN
F 2 "" H 4450 4150 50  0001 C CNN
F 3 "~" H 4450 4150 50  0001 C CNN
	1    4450 4150
	1    0    0    -1  
$EndComp
Wire Wire Line
	4450 4150 4450 4200
Text Notes 6400 2150 0    50   ~ 10
If back powering Pi with 5V \nNOTE that the Raspberry Pi 3B+ and Pi Zero \nand ZeroW do not include an input ZVD.
Wire Notes Line
	6350 1850 6350 2200
Wire Notes Line
	6350 2200 8200 2200
Wire Notes Line
	8200 2200 8200 1850
Wire Notes Line
	8200 1850 6350 1850
Wire Wire Line
	4800 2050 5050 2050
Wire Wire Line
	4400 2050 4400 1950
Wire Wire Line
	4400 2050 4800 2050
$Comp
L power:PWR_FLAG #FLG0103
U 1 1 5C77CEFA
P 6200 1950
F 0 "#FLG0103" H 6200 2025 50  0001 C CNN
F 1 "PWR_FLAG" H 6200 2124 50  0000 C CNN
F 2 "" H 6200 1950 50  0001 C CNN
F 3 "~" H 6200 1950 50  0001 C CNN
	1    6200 1950
	1    0    0    -1  
$EndComp
Wire Wire Line
	5850 2050 6200 2050
Wire Wire Line
	6200 1950 6200 2050
Text Label 4100 2150 0    50   ~ 0
GPIO2_SDA1
Text Label 4100 2250 0    50   ~ 0
GPIO3_SCL1
Text Label 4100 2350 0    50   ~ 0
GPIO4_GPIO_GCLK
Text Label 4100 2550 0    50   ~ 0
GPIO17_GEN0
Text Label 4100 2650 0    50   ~ 0
GPIO27_GEN2
Text Label 4100 2750 0    50   ~ 0
GPIO22_GEN3
Text Label 4100 2950 0    50   ~ 0
GPIO10_SPI_MOSI
Wire Wire Line
	4000 2950 5050 2950
Wire Wire Line
	4000 3050 5050 3050
Wire Wire Line
	4000 3150 5050 3150
Wire Wire Line
	4000 3350 5050 3350
Wire Wire Line
	4000 3450 5050 3450
Wire Wire Line
	4000 3550 5050 3550
Wire Wire Line
	4000 3650 5050 3650
Wire Wire Line
	4000 3750 5050 3750
Wire Wire Line
	4000 3850 5050 3850
Wire Wire Line
	4000 2750 5050 2750
Wire Wire Line
	4000 2650 5050 2650
Wire Wire Line
	4000 2550 5050 2550
Wire Wire Line
	4000 2350 5050 2350
Wire Wire Line
	4000 2250 5050 2250
Wire Wire Line
	4000 2150 5050 2150
Text Label 4100 3050 0    50   ~ 0
GPIO9_SPI_MISO
Text Label 4100 3150 0    50   ~ 0
GPIO11_SPI_SCLK
Text Label 4100 3350 0    50   ~ 0
ID_SD
Text Label 4100 3450 0    50   ~ 0
GPIO5
Text Label 4100 3550 0    50   ~ 0
GPIO6
Text Label 4100 3650 0    50   ~ 0
GPIO13
Text Label 4100 3750 0    50   ~ 0
GPIO19
Text Label 4100 3850 0    50   ~ 0
GPIO26
NoConn ~ 4000 2150
NoConn ~ 4000 2250
NoConn ~ 4000 2350
NoConn ~ 4000 2550
NoConn ~ 4000 2650
NoConn ~ 4000 2750
NoConn ~ 4000 2950
NoConn ~ 4000 3050
NoConn ~ 4000 3150
NoConn ~ 4000 3350
NoConn ~ 4000 3450
NoConn ~ 4000 3550
NoConn ~ 4000 3650
NoConn ~ 4000 3750
NoConn ~ 4000 3850
Text Label 5900 2350 0    50   ~ 0
GPIO14_TXD0
Text Label 5900 2450 0    50   ~ 0
GPIO15_RXD0
Text Label 5900 2550 0    50   ~ 0
GPIO18_GEN1
Text Label 5900 2750 0    50   ~ 0
GPIO23_GEN4
Text Label 5900 2850 0    50   ~ 0
GPIO24_GEN5
Text Label 5900 3050 0    50   ~ 0
GPIO25_GEN6
Text Label 5900 3150 0    50   ~ 0
GPIO8_SPI_CE0_N
Text Label 5900 3250 0    50   ~ 0
GPIO7_SPI_CE1_N
Wire Wire Line
	5550 3150 6600 3150
Wire Wire Line
	5550 3250 6600 3250
Text Label 5900 3350 0    50   ~ 0
ID_SC
Text Label 5900 3550 0    50   ~ 0
GPIO12
Text Label 5900 3750 0    50   ~ 0
GPIO16
Text Label 5900 3850 0    50   ~ 0
GPIO20
Text Label 5900 3950 0    50   ~ 0
GPIO21
Wire Wire Line
	5550 2350 6600 2350
Wire Wire Line
	5550 2450 6600 2450
Wire Wire Line
	5550 2550 6600 2550
Wire Wire Line
	5550 2750 6600 2750
Wire Wire Line
	5550 2850 6600 2850
Wire Wire Line
	5550 3050 6600 3050
Wire Wire Line
	5550 3350 6600 3350
Wire Wire Line
	5550 3550 6600 3550
Wire Wire Line
	5550 3750 6600 3750
Wire Wire Line
	5550 3850 6600 3850
NoConn ~ 6600 2350
NoConn ~ 6600 2450
NoConn ~ 6600 2550
NoConn ~ 6600 2750
NoConn ~ 6600 2850
NoConn ~ 6600 3050
NoConn ~ 6600 3150
NoConn ~ 6600 3250
NoConn ~ 6600 3350
NoConn ~ 6600 3550
NoConn ~ 6600 3750
NoConn ~ 6600 3850
NoConn ~ 6600 3950
Wire Wire Line
	5550 3950 6600 3950
$Comp
L Mechanical:MountingHole H1
U 1 1 5C7C4C81
P 8250 2600
F 0 "H1" H 8350 2646 50  0000 L CNN
F 1 "MountingHole" H 8350 2555 50  0000 L CNN
F 2 "lib:MountingHole_2.7mm_M2.5_uHAT_RPi" H 8250 2600 50  0001 C CNN
F 3 "~" H 8250 2600 50  0001 C CNN
	1    8250 2600
	1    0    0    -1  
$EndComp
$Comp
L Mechanical:MountingHole H2
U 1 1 5C7C7FBC
P 8250 2800
F 0 "H2" H 8350 2846 50  0000 L CNN
F 1 "MountingHole" H 8350 2755 50  0000 L CNN
F 2 "lib:MountingHole_2.7mm_M2.5_uHAT_RPi" H 8250 2800 50  0001 C CNN
F 3 "~" H 8250 2800 50  0001 C CNN
	1    8250 2800
	1    0    0    -1  
$EndComp
$Comp
L Mechanical:MountingHole H3
U 1 1 5C7C8014
P 8250 3000
F 0 "H3" H 8350 3046 50  0000 L CNN
F 1 "MountingHole" H 8350 2955 50  0000 L CNN
F 2 "lib:MountingHole_2.7mm_M2.5_uHAT_RPi" H 8250 3000 50  0001 C CNN
F 3 "~" H 8250 3000 50  0001 C CNN
	1    8250 3000
	1    0    0    -1  
$EndComp
$Comp
L Mechanical:MountingHole H4
U 1 1 5C7C8030
P 8250 3200
F 0 "H4" H 8350 3246 50  0000 L CNN
F 1 "MountingHole" H 8350 3155 50  0000 L CNN
F 2 "lib:MountingHole_2.7mm_M2.5_uHAT_RPi" H 8250 3200 50  0001 C CNN
F 3 "~" H 8250 3200 50  0001 C CNN
	1    8250 3200
	1    0    0    -1  
$EndComp
$EndSCHEMATC
