rule Ransom_Win32_Morsp_ST_2147762665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Morsp.ST!MTB"
        threat_id = "2147762665"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Morsp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files on your computers are encoded by a hard algorithm" ascii //weight: 1
        $x_1_2 = "DO NOT DELETE the encrypted and readme files" ascii //weight: 1
        $x_1_3 = "To get information how to decrypt your files, write to us at the address below:" ascii //weight: 1
        $x_1_4 = "*.morseop-" ascii //weight: 1
        $x_1_5 = "re-decrypt file %ws, %ws" ascii //weight: 1
        $x_1_6 = "After receiving bitcoins We will send you any you need to restore normal operation of your network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

