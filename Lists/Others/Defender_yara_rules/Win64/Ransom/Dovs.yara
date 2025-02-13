rule Ransom_Win64_Dovs_CRDA_2147850319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Dovs.CRDA!MTB"
        threat_id = "2147850319"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Dovs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\target\\release\\deps\\rcrypt.pdb" ascii //weight: 1
        $x_1_2 = "Content-RangeChunk  uploaded successfully!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

