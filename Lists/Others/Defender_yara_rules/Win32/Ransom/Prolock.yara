rule Ransom_Win32_Prolock_PA_2147752756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Prolock.PA!MTB"
        threat_id = "2147752756"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Prolock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProLock Ransomware" ascii //weight: 1
        $x_1_2 = "\\[HOW TO RECOVER FILES].TXT" wide //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "\\H0w_T0_Rec0very_Files.txt" wide //weight: 1
        $x_1_5 = ":\\Programdata\\lock.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

