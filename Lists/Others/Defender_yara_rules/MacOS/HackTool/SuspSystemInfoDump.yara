rule HackTool_MacOS_SuspSystemInfoDump_A1_2147932504_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.A1"
        threat_id = "2147932504"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; dscl . list /groups" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; dscl . list /users" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_B1_2147932505_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.B1"
        threat_id = "2147932505"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; who" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_C1_2147932506_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.C1"
        threat_id = "2147932506"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; /usr/bin/sw_vers -productversion" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_D1_2147932507_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.D1"
        threat_id = "2147932507"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; hostname" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; arp -a" wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; netstat -nltu" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_E1_2147932508_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.E1"
        threat_id = "2147932508"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; perl -v" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_G1_2147932509_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.G1"
        threat_id = "2147932509"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; mount" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_H1_2147932510_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.H1"
        threat_id = "2147932510"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; system_profiler spprintersdatatype" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; system_profiler spbluetoothdatatype" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_J1_2147932511_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.J1"
        threat_id = "2147932511"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; df -ah" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_M1_2147932512_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.M1"
        threat_id = "2147932512"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; sharing -l" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspSystemInfoDump_N1_2147932513_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspSystemInfoDump.N1"
        threat_id = "2147932513"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspSystemInfoDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; sw_vers -productname" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

