rule Trojan_Win64_FileCrypter_LVK_2147969751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCrypter.LVK!MTB"
        threat_id = "2147969751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 d0 89 c2 80 34 13 5a 8d 50 01 39 ca 73 3b 80 34 13 5a 8d 50 02 39 ca 73 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

