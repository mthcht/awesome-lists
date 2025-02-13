rule Trojan_Win32_Caiijin_17727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caiijin"
        threat_id = "17727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caiijin"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ijingcai.com/keyword" ascii //weight: 1
        $x_1_2 = "&adright=%s" ascii //weight: 1
        $x_1_3 = "96633122-0103-9638-2964-a87423648921" ascii //weight: 1
        $x_1_4 = "12365484-96a1-6974-3269-123555124655" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Caiijin_17727_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caiijin"
        threat_id = "17727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caiijin"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ijingcai.com/" ascii //weight: 1
        $x_1_2 = "\\drivers\\msrxmcb.sys" ascii //weight: 1
        $x_1_3 = "\\drivers\\tdac.sys" ascii //weight: 1
        $x_1_4 = "bhobhobbbad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

