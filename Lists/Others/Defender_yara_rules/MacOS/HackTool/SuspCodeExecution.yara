rule HackTool_MacOS_SuspCodeExecution_PA_2147932060_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCodeExecution.PA"
        threat_id = "2147932060"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCodeExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; gcc /tmp/sb-" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspCodeExecution_PB_2147932061_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCodeExecution.PB"
        threat_id = "2147932061"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCodeExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; touch -t " wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; touch -at " wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; touch -mt " wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; touch -a /tmp/sb_" wide //weight: 10
        $x_10_5 = "_bs >/dev/null ; touch -m /tmp/sb_" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspCodeExecution_PC_2147932062_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCodeExecution.PC"
        threat_id = "2147932062"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCodeExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; uptime" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; sleep " wide //weight: 10
        $x_10_3 = "_bs >/dev/null ; ping www." wide //weight: 10
        $x_10_4 = "_bs >/dev/null ; who -a" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_MacOS_SuspCodeExecution_PD_2147932063_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCodeExecution.PD"
        threat_id = "2147932063"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCodeExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; launchctl submit -l com." wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspCodeExecution_PE_2147932064_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspCodeExecution.PE"
        threat_id = "2147932064"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspCodeExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; osascript -e " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

