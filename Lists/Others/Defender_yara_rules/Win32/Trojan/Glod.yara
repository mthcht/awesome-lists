rule Trojan_Win32_Glod_A_2147660366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glod.A"
        threat_id = "2147660366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<input type=\"submit\" value=\"hm\" name=\"B1\">" ascii //weight: 1
        $x_1_2 = "C:\\Pic.bat" wide //weight: 1
        $x_1_3 = "C:\\Pic.jpg" wide //weight: 1
        $x_1_4 = {2f 00 68 00 74 00 [0-2] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_3_5 = "Keyspy Running On System" wide //weight: 3
        $x_1_6 = "\\don.exe" wide //weight: 1
        $x_1_7 = "\\donx.exe" wide //weight: 1
        $x_1_8 = {5b 00 45 00 73 00 63 00 61 00 70 00 65 00 5d 00 00 00 00 00 ?? 00 00 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {26 6e 62 73 70 3b 26 6e 62 73 70 3b 0d 0a 20 20 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 74 65 78 74 22 20 6e 61 6d 65 3d 22 70 63 6e 61 6d 65 22}  //weight: 1, accuracy: High
        $x_1_10 = "Are You Sure You Want To Clear Log" wide //weight: 1
        $x_1_11 = "www.samair.ru/proxy/proxychecker" wide //weight: 1
        $x_1_12 = "mail-cax.com/web.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glod_B_2147682291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glod.B"
        threat_id = "2147682291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 73 74 61 72 74 73 65 78 00}  //weight: 1, accuracy: High
        $x_1_2 = "openv" wide //weight: 1
        $x_1_3 = "[ALTDOWN]" wide //weight: 1
        $x_1_4 = "[Paste]" wide //weight: 1
        $x_1_5 = "Settimess" wide //weight: 1
        $x_1_6 = "Timess" wide //weight: 1
        $x_1_7 = "logss" wide //weight: 1
        $x_1_8 = "\\Mail1.htm" wide //weight: 1
        $x_1_9 = "/proxychecker/country.htm" wide //weight: 1
        $x_1_10 = "putratS\\smargorP\\uneM tratS\\swodniW\\tfosorciM\\gnimaoR\\ataDppA" wide //weight: 1
        $x_1_11 = {37 00 31 00 31 00 35 00 36 00 39 00 33 00 [0-8] 26 00 26 00 2a 00 2a 00 45 00 52 00 52 00 4f 00 52 00 2a 00 2a 00 26 00 26 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Glod_C_2147688398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glod.C"
        threat_id = "2147688398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[ALTDOWN]" wide //weight: 1
        $x_1_2 = "[Paste]" wide //weight: 1
        $x_1_3 = "Settimess" wide //weight: 1
        $x_1_4 = "\\Mail1.htm" wide //weight: 1
        $x_1_5 = "/XcountryX.php" wide //weight: 1
        $x_1_6 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 20 00 [0-27] 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

