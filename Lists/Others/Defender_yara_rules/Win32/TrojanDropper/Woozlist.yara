rule TrojanDropper_Win32_Woozlist_A_2147694059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Woozlist.A"
        threat_id = "2147694059"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Woozlist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-22] 2f 52 65 6d 6f 74 65 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {00 70 6f 70 75 70 [0-2] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "src=\"%url%\"></iframe>" ascii //weight: 1
        $x_1_5 = {00 50 6f 6c 69 63 79 41 67 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "ws2_32.dll\\hookdf" ascii //weight: 1
        $x_1_7 = "%s\\cmd /c rd \"%s\" /S /Q" ascii //weight: 1
        $x_1_8 = {52 61 6e 64 6f 6d 4f 70 65 6e 55 72 6c [0-32] 4c 6f 63 6b 48 6f 73 74 73 [0-32] 43 6f 6e 74 72 6f 6c 49 45 [0-32] 45 6d 62 65 64 55 72 6c}  //weight: 1, accuracy: Low
        $x_3_9 = "ProcessMointer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Woozlist_B_2147697733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Woozlist.B"
        threat_id = "2147697733"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Woozlist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "krnln.fnr" ascii //weight: 1
        $x_1_2 = {69 65 78 74 33 [0-3] 7b 42 36 46 37 35 34 32 46 2d 42 38 46 45 2d 34 36 61 38 2d 39 36 30 35 2d 39 38 38 35 36 41 36 38 37 30 39 37 7d}  //weight: 1, accuracy: Low
        $x_1_3 = "\\DosDevices\\baby" wide //weight: 1
        $x_1_4 = {2e 73 79 73 [0-5] 50 61 73 74}  //weight: 1, accuracy: Low
        $x_5_5 = {5c 65 74 63 5c 68 6f 73 74 73 [0-16] 68 74 74 70 3a 2f 2f}  //weight: 5, accuracy: Low
        $x_5_6 = "/gonggao.txt/" ascii //weight: 5
        $x_5_7 = ".tmp" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Woozlist_B_2147697733_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Woozlist.B"
        threat_id = "2147697733"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Woozlist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dywt.com.cn" ascii //weight: 1
        $x_1_2 = "=?gb2312?B?" ascii //weight: 1
        $x_1_3 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_4 = "707ca37322474f6ca841f0e224f4b620" ascii //weight: 1
        $x_1_5 = {5c 65 74 63 5c 68 6f 73 74 73 [0-16] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = "From: %s" ascii //weight: 1
        $x_1_7 = "Subject: %s" ascii //weight: 1
        $x_1_8 = "C:\\user.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Woozlist_B_2147697733_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Woozlist.B"
        threat_id = "2147697733"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Woozlist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dywt.com.cn" ascii //weight: 1
        $x_1_2 = "=?gb2312?B?" ascii //weight: 1
        $x_1_3 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_4 = "707ca37322474f6ca841f0e224f4b620" ascii //weight: 1
        $x_1_5 = "From: %s" ascii //weight: 1
        $x_1_6 = "Subject: %s" ascii //weight: 1
        $x_1_7 = {53 53 4f 41 78 43 74 72 6c 46 6f 72 50 54 4c 6f 67 69 6e 2e 53 53 4f 46 6f 72 50 54 4c 6f 67 69 6e 32 [0-16] 68 74 74 70 3a 2f 2f 78 75 69 2e 70 74 6c 6f 67 69 6e 32 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 71 6c 6f 67 69 6e [0-32] 53 69 6c 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_8 = "C:\\fsdlkjskl.exe" ascii //weight: 1
        $x_1_9 = {8b d1 57 8b f8 c1 e9 02 f3 a5 8b ca 55 83 e1 03 50 f3 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

