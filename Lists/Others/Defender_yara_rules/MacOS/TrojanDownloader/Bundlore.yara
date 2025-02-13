rule TrojanDownloader_MacOS_Bundlore_C_2147787467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Bundlore.C"
        threat_id = "2147787467"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Bundlore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chmod +x /private/" wide //weight: 2
        $x_2_2 = "chmod +x /var/" wide //weight: 2
        $x_3_3 = "/mm-install-macos.app/contents/macos/mm-install-macos" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MacOS_Bundlore_D_2147789221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Bundlore.D"
        threat_id = "2147789221"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Bundlore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nohup /bin/bash -c eval" wide //weight: 1
        $x_1_2 = "nohup /bin/sh -c eval" wide //weight: 1
        $x_2_3 = "openssl enc -aes-256-cbc -d -a -base64 -k" wide //weight: 2
        $x_2_4 = "xattr -c" wide //weight: 2
        $x_2_5 = "chmod 777" wide //weight: 2
        $x_2_6 = "&& rm -rf" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

