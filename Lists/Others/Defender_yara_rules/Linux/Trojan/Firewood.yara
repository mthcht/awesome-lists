rule Trojan_Linux_Firewood_A_2147937313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Firewood.A!MTB"
        threat_id = "2147937313"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Firewood"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "df -h|grep 'dev' |grep -v none|awk '/dev/{print $6}'" ascii //weight: 1
        $x_1_2 = "cat /proc/cpuinfo | grep \"model name\"" ascii //weight: 1
        $x_1_3 = "kill %d 2>/dev/null" ascii //weight: 1
        $x_1_4 = "insmod -f %s 2>/dev/null" ascii //weight: 1
        $x_1_5 = "X-GNOME-Autostart-enabled=true" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

