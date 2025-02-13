rule HackTool_Linux_PolkitPrivESC_A_2147783073_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PolkitPrivESC.A"
        threat_id = "2147783073"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PolkitPrivESC"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dbus-send --system" wide //weight: 2
        $x_2_2 = "--type=method_call" wide //weight: 2
        $x_2_3 = "org.freedesktop.Accounts" wide //weight: 2
        $x_2_4 = ".CreateUser" wide //weight: 2
        $x_2_5 = "User.SetPassword" wide //weight: 2
        $x_1_6 = "sleep" wide //weight: 1
        $x_1_7 = "kill $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

