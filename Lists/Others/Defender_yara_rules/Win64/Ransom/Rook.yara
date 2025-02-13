rule Ransom_Win64_Rook_GA_2147927842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rook.GA!MTB"
        threat_id = "2147927842"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Data at the main critical points of your network has been compromised, and all of your company's critical data has been transferred to our servers." ascii //weight: 1
        $x_1_2 = "Good news:" ascii //weight: 1
        $x_1_3 = "We can restore 100% of your systems and data." ascii //weight: 1
        $x_1_4 = "If we agree, only you and our team will know about this breach." ascii //weight: 1
        $x_1_5 = ".onion" ascii //weight: 1
        $x_1_6 = "Decryption and restoration of all your systems and data within 24 hours with a 100% guarantee;" ascii //weight: 1
        $x_1_7 = "Nothing personal, just business" ascii //weight: 1
        $x_1_8 = "read_me_to_access.txt" wide //weight: 1
        $x_1_9 = "log.txt" wide //weight: 1
        $x_1_10 = "key.pub" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

