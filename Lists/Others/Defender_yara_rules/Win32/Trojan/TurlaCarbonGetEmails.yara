rule Trojan_Win32_TurlaCarbonGetEmails_2147849792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonGetEmails"
        threat_id = "2147849792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonGetEmails"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Removing recipient:" wide //weight: 1
        $x_1_2 = "] Received mail item from" wide //weight: 1
        $x_1_3 = "] Blocking mail item from" wide //weight: 1
        $x_1_4 = "get_Attachments" ascii //weight: 1
        $x_1_5 = "EnvelopeRecipient" ascii //weight: 1
        $x_1_6 = "BlockMsg" ascii //weight: 1
        $x_1_7 = "get_Message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

