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

rule Trojan_MacOS_SuspDownloadExec_F_2147949647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspDownloadExec.F"
        threat_id = "2147949647"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspDownloadExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 00 73 00 63 00 6c 00 20 00 2e 00 [0-4] 61 00 75 00 74 00 68 00 6f 00 6e 00 6c 00 79 00}  //weight: 2, accuracy: Low
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = "curl -o" wide //weight: 1
        $x_1_4 = "xattr -c" wide //weight: 1
        $x_1_5 = "chmod +x" wide //weight: 1
        $x_1_6 = "curl -s -X POST http" wide //weight: 1
        $x_1_7 = ">/dev/null 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

