rule Trojan_Win64_UIDBypass_GVA_2147976315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UIDBypass.GVA!MTB"
        threat_id = "2147976315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UIDBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start /min cmd.exe" ascii //weight: 1
        $x_1_2 = "powershell -WindowStyle Hidden -Command" ascii //weight: 1
        $x_1_3 = {69 77 72 20 2d 55 72 69 20 27 68 74 74 70 73 3a 2f 2f 65 78 6f 2d 61 70 69 2e 74 66 2f 53 74 62 2f [0-10] 2e 70 68 70 3f 62 6c 3d [0-76] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {24 65 6e 76 3a 41 50 50 44 41 54 41 5c [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "Start-Process -FilePath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

