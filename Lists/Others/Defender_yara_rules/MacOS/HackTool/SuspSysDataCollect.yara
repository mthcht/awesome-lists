rule HackTool_MacOS_SuspSysDataCollect_BH1_2147930990_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.BH1"
        threat_id = "2147930990"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; locale -k lc_time" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; netstat -an" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; system_profiler SPUSBDataType" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_BH2_2147930991_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.BH2"
        threat_id = "2147930991"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; dscl . -list /Groups" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; ls -la /" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; pwpolicy getaccountpolicies" wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; locale" wide //weight: 10
        $x_10_5 = "_bs >/dev/null ; pfctl -s nat" wide //weight: 10
        $x_10_6 = "_bs >/dev/null ; uname -m" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_BH3_2147930992_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.BH3"
        threat_id = "2147930992"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; netstat -nap tcp" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; gcc -v" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; system_profiler SPUSBDataType" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_CH1_2147930993_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.CH1"
        threat_id = "2147930993"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; dscacheutil -q group" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; ls -la /Volumes" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ;/dev/null ; arch" wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; ioreg -p IOUSB -l -w0" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_CH2_2147930994_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.CH2"
        threat_id = "2147930994"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; history" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_EH1_2147930995_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.EH1"
        threat_id = "2147930995"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; security find-certificate -a -p > /dev/null" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; file /bin/pwd" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; cat /etc/resolv.conf" wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; ioreg" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_EH2_2147930996_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.EH2"
        threat_id = "2147930996"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; ifconfig -a" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; pfctl -s all" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_GH1_2147930997_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.GH1"
        threat_id = "2147930997"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; top -n 20 -l 1" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; ls /usr/lib/cron/tabs" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSysDataCollect_GH2_2147930998_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSysDataCollect.GH2"
        threat_id = "2147930998"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSysDataCollect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "_bs >/dev/null ; export histcontrol=ignorespace ; env | grep -q histcontrol" wide //weight: 10
        $x_10_2 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 64 00 69 00 67 00 20 00 2b 00 73 00 68 00 6f 00 72 00 74 00 20 00 6d 00 79 00 69 00 70 00 2e 00 6f 00 70 00 65 00 6e 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 20 00 [0-32] 2e 00 6f 00 70 00 65 00 6e 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

