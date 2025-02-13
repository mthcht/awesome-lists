rule Trojan_Win32_FkCryptor_SD_2147734521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FkCryptor.SD!MTB"
        threat_id = "2147734521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FkCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files have been encrypted" ascii //weight: 1
        $x_1_2 = "Well that's what happens when you watch porn on shady sites mate" ascii //weight: 1
        $x_1_3 = "All of your personal files have been encrypted with AES-256" ascii //weight: 1
        $x_1_4 = "And unlike other ransomware we don't want you to pay us anything" ascii //weight: 1
        $x_1_5 = "All you have to do is click the \"I'm gay\" button and sit through" ascii //weight: 1
        $x_1_6 = "If you're thinking about cheating - don't. We will detect that" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

