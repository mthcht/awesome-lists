rule PWS_Win32_Savnut_B_2147646218_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.B"
        threat_id = "2147646218"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%snetbanke_%s_%s" ascii //weight: 1
        $x_1_2 = "*xiti[*" ascii //weight: 1
        $x_1_3 = "&check=chck" ascii //weight: 1
        $x_2_4 = {81 3f 6e 6f 6e 65 74}  //weight: 2, accuracy: High
        $x_2_5 = {c7 07 55 53 46 3d af 33 c0}  //weight: 2, accuracy: High
        $x_2_6 = {b8 47 00 00 00 ba 6f 6f 67 6c b9 fc 0f 00 00 f2 ae}  //weight: 2, accuracy: High
        $x_2_7 = {ac aa 3c 40 75 fa 8b d7 8b 7d e8 8b cf b8 0a 00 00 00 f2 ae}  //weight: 2, accuracy: High
        $x_2_8 = {85 c0 74 08 8b 45 fc 80 38 40 75 0e ff 75 f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Savnut_A_2147646219_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.A"
        threat_id = "2147646219"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Mozilla\\Firefox\\extensions" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\McAfee\\MSC" ascii //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_4 = "%snetbanke_%s_%s" ascii //weight: 1
        $x_1_5 = {2a 00 5c 2a [0-16] 62 61 6e 6b 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Savnut_C_2147647325_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.C"
        threat_id = "2147647325"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromActiveX%08X%08X_%08d_%s" wide //weight: 1
        $x_1_2 = "FromJava%08X%08X_%08d_%Is" wide //weight: 1
        $x_1_3 = "\\*@abmr[*" ascii //weight: 1
        $x_1_4 = "INTO moz_cookies VALUES" ascii //weight: 1
        $x_2_5 = {3d 46 49 4e 5f 74 1d 3d 44 4f 4d 5f}  //weight: 2, accuracy: High
        $x_2_6 = {c7 44 38 fc 2e 74 78 74 53 53 ff 75 cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Savnut_D_2147648643_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.D"
        threat_id = "2147648643"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {46 00 72 00 6f 00 6d 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 5f 00 25 00 30 00 38 00 64 00 5f 00 25 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {46 00 72 00 6f 00 6d 00 4a 00 61 00 76 00 61 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 5f 00 25 00 30 00 38 00 64 00 5f 00 25 00 49 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = "%snetbanke_%s_%s" ascii //weight: 10
        $x_10_4 = "%s\\ffc_%s%d@%s.ffx" ascii //weight: 10
        $x_10_5 = "lodupgd.jpg" ascii //weight: 10
        $x_10_6 = "=ESP_tU=AUT_tN=COL_tG=ARG_t@=PER_t9=CHL_t2=ECU_t+=PAN_t$=FIN_t" ascii //weight: 10
        $x_2_7 = "&ver=" ascii //weight: 2
        $x_2_8 = "&data_type=" ascii //weight: 2
        $x_2_9 = "&data_content=" ascii //weight: 2
        $x_2_10 = "&check=chek" ascii //weight: 2
        $x_5_11 = "\\urhtps.dat" ascii //weight: 5
        $x_2_12 = "bankofamerica*" ascii //weight: 2
        $x_2_13 = "bankchangehost" ascii //weight: 2
        $x_2_14 = "ActivateProxy" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Savnut_E_2147649401_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.E"
        threat_id = "2147649401"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "xoz_cookies " ascii //weight: 2
        $x_2_2 = "scorecardresearch" ascii //weight: 2
        $x_2_3 = "\\urhtps.dat" ascii //weight: 2
        $x_2_4 = "%Is\\xmldm\\%Is.cfg" wide //weight: 2
        $x_2_5 = "%Is%sJava%08X%08X_%08d_%Is" wide //weight: 2
        $x_2_6 = "%s\\%s_%08d.lkey" ascii //weight: 2
        $x_2_7 = "%snetbanke_%s_%s" ascii //weight: 2
        $x_1_8 = "=DEU_tU=COL_tN=ESP_tG=AUT_t@=PER_t9" ascii //weight: 1
        $x_1_9 = {8b 45 e8 03 45 b0 c6 40 ff 5c 89 45 d8 8b 45 ec 03 45 b0 48}  //weight: 1, accuracy: High
        $x_8_10 = {ff 45 f8 89 5d b8 8d 0d ?? ?? ?? 00 8b 7d dc 66 c7 07 5c 2a 66 af 8a 01 aa 41 84 c0 75 f8}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Savnut_F_2147650512_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.F"
        threat_id = "2147650512"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 7f 01 74 74 70 73 0f 85 ?? 00 00 00 80 7f 08 41 0f 82 ?? 00 00 00 81 3d c0 0c 25 00 44 45 55 5f 75}  //weight: 2, accuracy: Low
        $x_1_2 = "\\srvblck2.tmp" ascii //weight: 1
        $x_1_3 = "bankchangehost:" ascii //weight: 1
        $x_1_4 = "\\urhtps.dat" ascii //weight: 1
        $x_1_5 = "%s\\%s_%08d.mpst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Savnut_G_2147652079_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Savnut.G"
        threat_id = "2147652079"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 7d dc 66 c7 07 5c 2a 66 af 8a 01 aa 41 84 c0 75 f8}  //weight: 3, accuracy: High
        $x_4_2 = {8b 7d f0 b8 47 00 00 00 ba 6f 6f 67 6c b9 fc 0f 00 00 8b c0 f2 ae e3 04 39 17 75 f6 51}  //weight: 4, accuracy: High
        $x_3_3 = {81 39 68 74 74 70 75 03 83 c1 07 51 e8}  //weight: 3, accuracy: High
        $x_3_4 = {74 11 8b 55 08 c6 02 e9 8b 45 0c 2b c2 83 e8 05 89 42 01}  //weight: 3, accuracy: High
        $x_1_5 = "&version2=586&vendor=Old" ascii //weight: 1
        $x_1_6 = "\\urhtps.tmp" ascii //weight: 1
        $x_1_7 = "%snetbanke_%s_%s" ascii //weight: 1
        $x_1_8 = "\\srvblck2.tmp" ascii //weight: 1
        $x_1_9 = "bankchangehost" ascii //weight: 1
        $x_1_10 = "%s\\%s_%08d.mpst" ascii //weight: 1
        $x_1_11 = "%s\\%s_%08d.lkey" ascii //weight: 1
        $x_1_12 = "xoz_cookies " ascii //weight: 1
        $x_2_13 = {c7 07 55 53 46 3d af 33 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

