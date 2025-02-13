rule Ransom_Win32_GenWaste_B_2147758065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GenWaste.B!MTB"
        threat_id = "2147758065"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GenWaste"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR NETWORK IS ENCRYPTED NOW" ascii //weight: 1
        $x_1_2 = "TO GET THE PRICE FOR YOUR DATA" ascii //weight: 1
        $x_1_3 = "DO NOT GIVE THIS EMAIL TO 3RD PARTIES" ascii //weight: 1
        $x_1_4 = "DO NOT RENAME OR MOVE THE FILE" ascii //weight: 1
        $x_1_5 = "THE FILE IS ENCRYPTED WITH THE FOLLOWING KEY:" ascii //weight: 1
        $x_1_6 = "[begin_key]%S[end_key]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

