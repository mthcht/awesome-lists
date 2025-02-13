rule Trojan_Win32_Ransirac_A_2147653621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ransirac.A"
        threat_id = "2147653621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransirac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "landing.qpoe.com:8080/popka/?u=6&id=" ascii //weight: 4
        $x_2_2 = "LockWindowsBot\\Project\\AntiPirate" ascii //weight: 2
        $x_2_3 = "winlock\\AntiPirate\\Release" ascii //weight: 2
        $x_2_4 = "InetAccelerator\\InetAccelerator.exe" ascii //weight: 2
        $x_2_5 = "delete HKLM\\System\\Curr" ascii //weight: 2
        $x_1_6 = "AHrefGoToYourself" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ransirac_C_2147654066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ransirac.C"
        threat_id = "2147654066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransirac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zalupa/?id=" ascii //weight: 1
        $x_1_2 = {6a 64 6a 03 51 ff d7 8b 56 20 6a 00 6a 01 6a 06 52 ff d7 68 88 13 00 00 ff d3 6a 00}  //weight: 1, accuracy: High
        $x_1_3 = "{6E9675F9-C7C4-448e-80F6-CDF25448C47E}" ascii //weight: 1
        $x_1_4 = "InetAccelerator" ascii //weight: 1
        $x_1_5 = "7h6kh9l8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Ransirac_G_2147654449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ransirac.G"
        threat_id = "2147654449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransirac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e [0-32] 73 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e [0-32] 75 73 65 72 69 6e 69 74}  //weight: 1, accuracy: Low
        $x_1_4 = {67 65 6d 61 5c 67 65 6d 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "/zalupa/?id=" ascii //weight: 1
        $x_1_6 = "BUTTON_ENTER_SERIAL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ransirac_A_2147655054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ransirac.gen!A"
        threat_id = "2147655054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransirac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 31 53 53 6a 4e 57 ff 15 ?? ?? ?? ?? 53 8d 85 ?? ?? ?? ?? 50 6a 08 56 57 ff 15 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 56 88 5e 08 ff 15 ?? ?? ?? ?? 88 1c 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

