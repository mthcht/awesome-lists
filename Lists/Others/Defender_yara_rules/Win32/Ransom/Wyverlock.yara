rule Ransom_Win32_Wyverlock_PA_2147760692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wyverlock.PA!MTB"
        threat_id = "2147760692"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wyverlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xienvkdoc" ascii //weight: 1
        $x_1_2 = "desktop.ini" ascii //weight: 1
        $x_1_3 = "autorun.inf" ascii //weight: 1
        $x_1_4 = "Tor Browser" ascii //weight: 1
        $x_5_5 = "_READ_ME_.txt" ascii //weight: 5
        $x_5_6 = {5c 77 79 76 65 72 6e 6c 6f 63 6b 65 72 5c [0-16] 5c 77 79 76 65 72 6e 6c 6f 63 6b 65 72 2e 70 64 62}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

