rule Trojan_Linux_Showboat_DA_2147969967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Showboat.DA!MTB"
        threat_id = "2147969967"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Showboat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/ld.so.preload" ascii //weight: 1
        $x_1_2 = "dlsym(RTLD_NEXT, #readdir)" ascii //weight: 1
        $x_1_3 = "/proc/self/exe" ascii //weight: 1
        $x_1_4 = "gcc -fPIC -shared" ascii //weight: 1
        $x_1_5 = "mv lib%s.so /usr/local/lib/" ascii //weight: 1
        $x_1_6 = "ExecStart=%s" ascii //weight: 1
        $x_1_7 = "Restart=always" ascii //weight: 1
        $x_1_8 = "/client/update" ascii //weight: 1
        $x_1_9 = "/client/events?uuid=" ascii //weight: 1
        $x_1_10 = "\"minSleep\":" ascii //weight: 1
        $x_1_11 = "\"maxSleep\":" ascii //weight: 1
        $x_1_12 = "\"client_id=" ascii //weight: 1
        $x_1_13 = "Process has been hidden." ascii //weight: 1
        $x_1_14 = "Hide precess success!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

