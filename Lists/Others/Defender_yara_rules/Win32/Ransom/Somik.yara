rule Ransom_Win32_Somik_PA_2147749278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Somik.PA!MTB"
        threat_id = "2147749278"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Somik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All your files have been encrypted due to a security problem with your PC." wide //weight: 1
        $x_1_2 = "How to obtain Bitcoins" wide //weight: 1
        $x_1_3 = "Do not attempt to use the antivirus or uninstall the program" wide //weight: 1
        $x_1_4 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 57 00 41 00 52 00 4e 00 49 00 4e 00 47 00 ?? ?? 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

