rule Ransom_Win64_FSociety_AMTB_2147969808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FSociety!AMTB"
        threat_id = "2147969808"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FSociety"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted by fsociety." ascii //weight: 1
        $x_1_2 = "We will DDoS your ISP and call your mom" ascii //weight: 1
        $x_1_3 = "[fsociety] Mission accomplished. Victim ID:" ascii //weight: 1
        $x_1_4 = "READ_ME_FSOCIETY.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

