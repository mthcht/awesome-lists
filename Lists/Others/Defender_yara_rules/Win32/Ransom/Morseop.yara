rule Ransom_Win32_Morseop_PA_2147762640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Morseop.PA!MTB"
        threat_id = "2147762640"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Morseop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptDisk(%ws) DONE" ascii //weight: 1
        $x_1_2 = "ransomware.exe" ascii //weight: 1
        $x_1_3 = "!!_FILES_ENCRYPTED_.txt" wide //weight: 1
        $x_1_4 = "Your network has been penetrated" ascii //weight: 1
        $x_1_5 = "ransomware.pdb" ascii //weight: 1
        $x_1_6 = "Cynet Ransom Protection(DON'T DELETE)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

