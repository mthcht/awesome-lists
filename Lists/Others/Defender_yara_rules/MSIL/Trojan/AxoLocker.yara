rule Trojan_MSIL_AxoLocker_AC_2147833581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AxoLocker.AC!MTB"
        threat_id = "2147833581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AxoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your presonal files are encrypted." wide //weight: 1
        $x_1_2 = "Reaper Ransomware" wide //weight: 1
        $x_1_3 = "DisableAntiSpyware" wide //weight: 1
        $x_1_4 = "C:\\win32.exe" wide //weight: 1
        $x_1_5 = "you kill or restart this program" wide //weight: 1
        $x_1_6 = "Desktop\\READ_ME.txt" wide //weight: 1
        $x_1_7 = "KeyBot" wide //weight: 1
        $x_1_8 = "Your photos, videos, documents, and other important files are encrypted by special key" ascii //weight: 1
        $x_1_9 = "How can i decrypt my files?" ascii //weight: 1
        $x_1_10 = "Wait for my response" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

