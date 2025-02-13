rule Ransom_Win32_UdochkCrypt_CM_2147771706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/UdochkCrypt.CM!MTB"
        threat_id = "2147771706"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "UdochkCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We got your documents and files encrypted" ascii //weight: 1
        $x_1_2 = "we will either send those data to rivals, or publish them. GDPR" ascii //weight: 1
        $x_1_3 = "pay 10x more to the government" ascii //weight: 1
        $x_1_4 = "Was ist gerade passiert?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

