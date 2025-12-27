rule Ransom_Win32_Lokibot_KGL_2147954954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lokibot.KGL!MTB"
        threat_id = "2147954954"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 ca 42 8a 04 29 32 01 88 04 0e 3b d7 72}  //weight: 5, accuracy: High
        $x_1_2 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "You only have 96 hours to submit the payment" ascii //weight: 1
        $x_1_4 = "Only we can decrypt the file!" ascii //weight: 1
        $x_1_5 = "The file is encrypted with the AES-256 algorithm" ascii //weight: 1
        $x_1_6 = "Do not hesitate, contact us immediately" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

