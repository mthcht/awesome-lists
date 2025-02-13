rule HackTool_AndroidOS_UsbCleaver_A_2147783174_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/UsbCleaver.A!MTB"
        threat_id = "2147783174"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "UsbCleaver"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "usbcleaver" ascii //weight: 1
        $x_1_2 = "Udpflood" ascii //weight: 1
        $x_1_3 = "www.bugtraq-team.com" ascii //weight: 1
        $x_1_4 = {63 70 20 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f [0-16] 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 62 75 67 74 72 6f 69 64 2f}  //weight: 1, accuracy: Low
        $x_1_5 = "chmod 777 /data/data/com.bugtroid/" ascii //weight: 1
        $x_1_6 = "Router Brute Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

