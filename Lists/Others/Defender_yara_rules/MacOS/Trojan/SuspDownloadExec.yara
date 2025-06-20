rule Trojan_MacOS_SuspDownloadExec_D_2147944298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspDownloadExec.D"
        threat_id = "2147944298"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspDownloadExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "curl " wide //weight: 4
        $x_4_2 = "https://raw.githubusercontent.com/psdb1337/" wide //weight: 4
        $x_1_3 = "/refs/heads/main/keylogger -o /private/tmp/" wide //weight: 1
        $x_1_4 = "/refs/heads/main/shellcoder -o /private/tmp/" wide //weight: 1
        $x_4_5 = "chmod +x /private/tmp" wide //weight: 4
        $x_4_6 = "&& /private/tmp/" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SuspDownloadExec_E_2147944299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspDownloadExec.E"
        threat_id = "2147944299"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspDownloadExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "touch /private/tmp" wide //weight: 1
        $x_1_2 = "curl " wide //weight: 1
        $x_1_3 = "/DyldDeNeuralyzer" wide //weight: 1
        $x_1_4 = "chmod +x /private/tmp" wide //weight: 1
        $x_1_5 = "&& /private/tmp/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

