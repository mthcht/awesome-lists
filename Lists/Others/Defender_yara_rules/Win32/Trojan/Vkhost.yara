rule Trojan_Win32_Vkhost_E_2147644264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vkhost.E"
        threat_id = "2147644264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vkhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be 99 b7 00 00 33 d2 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4e 75 e6}  //weight: 10, accuracy: Low
        $x_1_2 = ", liveinternet.ru" ascii //weight: 1
        $x_1_3 = ", odnoklassniki.ru" ascii //weight: 1
        $x_1_4 = ", virusbuster.hu" ascii //weight: 1
        $x_1_5 = ", go.mail.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

