rule Trojan_Win32_Vilorck_SA_2147760308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilorck.SA!MTB"
        threat_id = "2147760308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilorck"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 55 53 45 52 4e 41 4d 45 20 65 71 20 4a 6f 68 6e 44 6f 65 22 20 2f 46 20 2f 49 4d 20 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 20 22 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c [0-9] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = "choco.exe" ascii //weight: 1
        $x_1_4 = "fine is not paid within three days, a warrant will be issued for your arrest" wide //weight: 1
        $x_1_5 = "system has been compromised by extremists" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

