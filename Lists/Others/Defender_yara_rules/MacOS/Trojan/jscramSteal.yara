rule Trojan_MacOS_jscramSteal_DA_2147973454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/jscramSteal.DA!MTB"
        threat_id = "2147973454"
        type = "Trojan"
        platform = "MacOS: "
        family = "jscramSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gunzipSync" ascii //weight: 1
        $x_1_2 = "}from'child_process';import{tmpdir as" ascii //weight: 1
        $x_1_3 = "}from'zlib';import{spawn as" ascii //weight: 1
        $x_1_4 = "writeFileSync as" ascii //weight: 1
        $x_1_5 = "{detached:true,stdio:'ignore',windowsHide:true});" ascii //weight: 1
        $x_1_6 = "<key>KeepAlive</key>" ascii //weight: 1
        $x_1_7 = "<key>ProgramArguments</key>" ascii //weight: 1
        $x_1_8 = "<key>RunAtLoad</key>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

