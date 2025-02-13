rule Trojan_Win32_Powemet_2147725131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet"
        threat_id = "2147725131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String('H4sIAOSHM1oCA7VWbW/aSBD+nEr9D1aFhK0QbFJKaKRItzYmmOIEx2Deik6Ovdgbr1/OLwGn1/9+Y8AJaZJTqtNZS" ascii //weight: 1
        $x_1_2 = "1i9peGvS/bZcMi0XMycosAvZILTMAlVdjyhJ2er371VucdJY1uW/MpMmbFXPkxT7dZvSKsf85AqHozzCbFUlVhwm4SqtT0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powemet_A_2147725438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.A!attk"
        threat_id = "2147725438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-240] 2f 00 69 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-240] 2d 00 69 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Powemet_A_2147725438_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.A!attk"
        threat_id = "2147725438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "regsvr32" wide //weight: 5
        $x_1_2 = "/i:http" wide //weight: 1
        $x_1_3 = "-i:http" wide //weight: 1
        $x_10_4 = " scrobj.dll" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_A_2147725438_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.A!attk"
        threat_id = "2147725438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "regsvr32" wide //weight: 5
        $x_5_2 = "/s" wide //weight: 5
        $x_5_3 = "/u" wide //weight: 5
        $x_1_4 = "/i:http" wide //weight: 1
        $x_1_5 = "/i:\\\\" wide //weight: 1
        $x_5_6 = "scrobj.dll" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_D_2147725442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.D!attk"
        threat_id = "2147725442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 00 79 00 70 00 61 00 73 00 73 00 20 00 [0-8] 69 00 65 00 78 00 [0-4] 28 00 5b 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 61 00 73 00 63 00 69 00 69 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 67 00 70 00 20 00 27 00 68 00 6b 00 63 00 75 00 3a 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 63 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {62 00 79 00 70 00 61 00 73 00 73 00 20 00 [0-8] 69 00 65 00 78 00 [0-4] 28 00 5b 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 75 00 6e 00 69 00 63 00 6f 00 64 00 65 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 67 00 70 00 20 00 27 00 68 00 6b 00 63 00 75 00 3a 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 63 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Powemet_E_2147729715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.E"
        threat_id = "2147729715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "bypass" wide //weight: 1
        $x_1_3 = "hidden" wide //weight: 1
        $x_1_4 = "-encoded" wide //weight: 1
        $x_3_5 = "SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQA" wide //weight: 3
        $x_3_6 = "AEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6AC4AcABzADEA" wide //weight: 3
        $x_3_7 = "cwBlAGsAdQByAGwAcwBhADoAOg" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_J_2147730746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.J"
        threat_id = "2147730746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "113"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "\\powershell.exe" wide //weight: 100
        $x_10_2 = "$env:comspec[4,24,25]" wide //weight: 10
        $x_10_3 = "$shellid[1]+$shellid[13]+'x'" wide //weight: 10
        $x_5_4 = "23 ,5 , 119, 123 ,102" wide //weight: 5
        $x_5_5 = "41, 59 ,73 , 69 , 88," wide //weight: 5
        $x_5_6 = "bxor'0x3e')})" wide //weight: 5
        $x_5_7 = "([convert]::toint16(([string]$_) , 16) -as[char])})" wide //weight: 5
        $x_5_8 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 27 00 [0-3] 27 00 2d 00 73 00 70 00 6c 00 69 00 74 00 27 00 [0-3] 27 00 2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 27 00 [0-3] 27 00 20 00 2d 00 73 00 70 00 6c 00 69 00 74 00}  //weight: 5, accuracy: Low
        $x_1_9 = "-nop" wide //weight: 1
        $x_1_10 = "-wind" wide //weight: 1
        $x_1_11 = "-exec byp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_F_2147741515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.F"
        threat_id = "2147741515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\WMIC.exe" wide //weight: 1
        $x_1_2 = "'PRocEss'" wide //weight: 1
        $x_1_3 = " CrEate " wide //weight: 1
        $x_1_4 = "CoNveRT]::FROMBaSe64STRInG(" wide //weight: 1
        $x_1_5 = "$shEllID[1]+$shelliD[13]+'x')" wide //weight: 1
        $x_1_6 = ".READtoeNd(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powemet_B_2147757077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.B!attk"
        threat_id = "2147757077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "regsvr32" wide //weight: 5
        $x_1_2 = "/i:url:http" wide //weight: 1
        $x_1_3 = "-i:url:http" wide //weight: 1
        $x_10_4 = " scrobj.dll" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_K_2147788208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.K!attk"
        threat_id = "2147788208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $n_100_1 = ".dll" wide //weight: -100
        $x_10_2 = "regsvr32" wide //weight: 10
        $x_1_3 = ".jpg" wide //weight: 1
        $x_1_4 = ".csv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_L_2147789148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.L!attk"
        threat_id = "2147789148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "regsvr32" wide //weight: 10
        $x_10_2 = "scrobj.dll" wide //weight: 10
        $x_10_3 = ".sct" wide //weight: 10
        $x_1_4 = " /i:" wide //weight: 1
        $x_1_5 = " -i:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powemet_SA_2147799338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.SA!attk"
        threat_id = "2147799338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-240] 2f 00 69 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-240] 2d 00 69 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_3 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-240] 2f 00 69 00 3a 00 66 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_4 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-240] 2d 00 69 00 3a 00 66 00 74 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Powemet_G_2147836254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.G!attk"
        threat_id = "2147836254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " scrobj.dll " wide //weight: 1
        $x_1_3 = " /s " wide //weight: 1
        $x_1_4 = " /u " wide //weight: 1
        $x_1_5 = " /n " wide //weight: 1
        $x_5_6 = " /i:../../../Users/Public/" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

