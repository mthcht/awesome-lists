rule HackTool_MacOS_SuspiousDataCollect_X_2147931747_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspiousDataCollect.X"
        threat_id = "2147931747"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspiousDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; syslog" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; whoami" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; uname -a" wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; dmesg" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspiousDataCollect_Y_2147931748_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspiousDataCollect.Y"
        threat_id = "2147931748"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspiousDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; cat /etc/hosts" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; ps aux" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; ifconfig" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspiousDataCollect_Z_2147931749_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspiousDataCollect.Z"
        threat_id = "2147931749"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspiousDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; crontab -l" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; cat /etc/sudoers" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; netstat anop" wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; who -a" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

