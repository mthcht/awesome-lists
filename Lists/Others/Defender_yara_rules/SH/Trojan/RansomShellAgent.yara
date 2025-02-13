rule Trojan_SH_RansomShellAgent_E8_2147924921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:SH/RansomShellAgent.E8"
        threat_id = "2147924921"
        type = "Trojan"
        platform = "SH: Shell scripts"
        family = "RansomShellAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "mdatp config real-time-protection --value disabled" wide //weight: 5
        $x_5_2 = "mdatp config cloud --value disabled" wide //weight: 5
        $x_5_3 = "rpm -e cb-psc-sensor" wide //weight: 5
        $x_5_4 = "dpkg --purge cb-psc-sensor" wide //weight: 5
        $x_5_5 = "mdatp config passive-mode --value enabled" wide //weight: 5
        $x_5_6 = "systemctl stop mdatp" wide //weight: 5
        $x_5_7 = "rm -rf /var/opt/carbonblack" wide //weight: 5
        $x_15_8 = {20 00 2d 00 66 00 61 00 73 00 74 00 20 00 2d 00 70 00 61 00 73 00 73 00 20 00 [0-80] 20 00 2d 00 70 00 61 00 74 00 68 00 20 00 2f 00}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

