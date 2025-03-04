rule Trojan_Linux_Finspy_A_2147770026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Finspy.A!!Finspy.A"
        threat_id = "2147770026"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Finspy"
        severity = "Critical"
        info = "Finspy: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a5 aa ca a6 54 5a ?? ?? 5a a5 0a}  //weight: 10, accuracy: Low
        $x_1_2 = {7f 0d 45 4c 46 01 02 c2 14 68 03 05 0e}  //weight: 1, accuracy: High
        $x_1_3 = {7f 07 45 4c 46 02 01 1e 15 01 8e 03 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Finspy_A_2147770026_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Finspy.A!!Finspy.A"
        threat_id = "2147770026"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Finspy"
        severity = "Critical"
        info = "Finspy: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s/.kde/Autostart" ascii //weight: 10
        $x_1_2 = "%s/.kde4/Autostart" ascii //weight: 1
        $x_1_3 = "%s/.bash_profile" ascii //weight: 1
        $x_1_4 = "g_pinstall_host_location" ascii //weight: 1
        $x_1_5 = "g_plauncher" ascii //weight: 1
        $x_1_6 = "hypervisor detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Finspy_A_2147770026_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Finspy.A!!Finspy.A"
        threat_id = "2147770026"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Finspy"
        severity = "Critical"
        info = "Finspy: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ps auxww | grep -iEe 'bt-scan' | grep -v -e grep" ascii //weight: 1
        $x_1_2 = "%s/.kde4/share/config" ascii //weight: 1
        $x_1_3 = "/etc/hostname-merlin" ascii //weight: 1
        $x_1_4 = "%s/.bash_profile1" ascii //weight: 1
        $x_1_5 = "/index.php HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

