rule Trojan_Win32_Taranis_MBXS_2147919770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taranis.MBXS!MTB"
        threat_id = "2147919770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taranis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iuuq;00zn/uvqjbo9/do0sfqpsu0sfqpsu/qiq" ascii //weight: 1
        $x_1_2 = "asf{mtrj3myr" ascii //weight: 1
        $x_1_3 = "`otptjejhjemghgstehqiqrirtrhhtrnm`52424c4`nuyiv}2qmr2nw" ascii //weight: 1
        $x_1_4 = "a8;5HmwtrjaHmwtrjaZxjw%IfyfaIjkfzqy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

