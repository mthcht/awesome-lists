rule Trojan_MacOS_GlassWorm_HAB_2147956443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GlassWorm.HAB!MTB"
        threat_id = "2147956443"
        type = "Trojan"
        platform = "MacOS: "
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "/lib.rsdecodegenerate_secret_key_hvnc::decode/" ascii //weight: 30
        $x_1_2 = "napi_run_scriptnapi_create_async" ascii //weight: 1
        $x_1_3 = "/entry.rs/rustc/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_GlassWorm_A_2147962229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GlassWorm.A!MTB"
        threat_id = "2147962229"
        type = "Trojan"
        platform = "MacOS: "
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rust_implant/target/release/deps/librust_implant.dylib" ascii //weight: 1
        $x_1_2 = {e0 ef c4 3d e1 f3 c4 3d e0 77 84 3d e1 7b 84 3d e0 fb c4 3d e1 f7 c4 3d e0 83 84 3d e1 7f 84 3d e0 df c4 3d e1 e3 c4 3d e0 67 84 3d e1 6b 84 3d e0 eb c4 3d e1 e7 c4 3d e0 73 84 3d e1 6f 84 3d e0 db c4 3d e1 d7 c4 3d}  //weight: 1, accuracy: High
        $x_1_3 = {28 00 80 52 a8 e2 0f 39 ea 07 40 91 4a 41 28 91 48 31 40 b8 48 71 05 b8 e8 13 5a b9 e8 67 1a b9 f4 a3 0f 91 80 82 c9 3c 40 0d 80 3d e8 4b 42 f9 e8 2b 0d f9 e9 67 5a b9 a9 03 13 b8 49 71 45 b8 ea 07 40 91 4a 21 38 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MacOS_GlassWorm_B_2147962230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GlassWorm.B!MTB"
        threat_id = "2147962230"
        type = "Trojan"
        platform = "MacOS: "
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dropper_banLibrary" ascii //weight: 1
        $x_1_2 = "com.apple.updeventslaunchctlremove" ascii //weight: 1
        $x_1_3 = "xattr -c  && chmod 777 sh-ccom.apple.dockstorage" ascii //weight: 1
        $x_1_4 = "RunPayloadinputbinPayloadOutputokoutputloader_running" ascii //weight: 1
        $x_1_5 = "Storageserver_urlserver_recovery" ascii //weight: 1
        $x_1_6 = "PayloadOutputokloader_running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

