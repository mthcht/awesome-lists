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

rule Trojan_MacOS_SuspDownloadExec_G_2147949992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspDownloadExec.G"
        threat_id = "2147949992"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspDownloadExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 00 73 00 63 00 6c 00 20 00 2e 00 [0-4] 61 00 75 00 74 00 68 00 6f 00 6e 00 6c 00 79 00}  //weight: 2, accuracy: Low
        $x_2_2 = "dscl /local/default -authonly" wide //weight: 2
        $x_3_3 = "whoami" wide //weight: 3
        $x_3_4 = "curl -o" wide //weight: 3
        $x_3_5 = "xattr -c" wide //weight: 3
        $x_3_6 = "chmod +x" wide //weight: 3
        $x_3_7 = ">/dev/null 2>&1" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SuspDownloadExec_SA_2147963443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspDownloadExec.SA"
        threat_id = "2147963443"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspDownloadExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "curl " wide //weight: 50
        $x_1_2 = "-s https://kenaikoda.com/api/mn/" wide //weight: 1
        $x_1_3 = "-s https://zoom.uso5web.us/api/mn/" wide //weight: 1
        $x_1_4 = "-s https://uw04webzoom.us/developer/sdk/fix" wide //weight: 1
        $x_1_5 = "-s https://uw04webzoom.us/fix/mac/update/status/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

