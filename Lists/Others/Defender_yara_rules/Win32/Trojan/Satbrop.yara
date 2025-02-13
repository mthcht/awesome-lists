rule Trojan_Win32_Satbrop_A_2147718498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satbrop.A"
        threat_id = "2147718498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satbrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b cb 66 ba b8 0b 8b 45 fc e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 40 00 8d 45 fc e8 ?? ?? ff ff c3}  //weight: 4, accuracy: Low
        $x_2_2 = "JxSoqd7HlPzCcC" ascii //weight: 2
        $x_2_3 = "Gh7kOXLlDCJD/NnXBnCB7Vm8xpnInLlIk3pAuDYkY/MgfvJxQIJwudvt3Pg9MFdwye8nMY2WEYb4WsUn14Rd" ascii //weight: 2
        $x_2_4 = "YRjMiR5pJQ2BS01054IZ+IU8u00RCk2L9tm+lACTf28OI7vow9xZfWqV7V0q" ascii //weight: 2
        $x_2_5 = "YRjMiR5pJQ2BYQGnxrtHJr/rc1ldUMq+LwntFlv2clCGXRO+WLP" ascii //weight: 2
        $x_2_6 = "YJAUKNorqeSv5Xr4LhVuuxPAjqDek78PMkXhVHjkeMd7zTi7" ascii //weight: 2
        $x_2_7 = "YRjMiR5pJQ2BeUoQ648el9DVFta9CWKqhycjWD" ascii //weight: 2
        $x_1_8 = "4BlRErxQhNzeXjfPts2qkwZsmRZ" ascii //weight: 1
        $x_1_9 = "XBM9azSbXuRt42aoli2T9soP0C" ascii //weight: 1
        $x_1_10 = "j5kmNVnZPA" ascii //weight: 1
        $x_1_11 = "uBGZFt2UKm+ObBe0" ascii //weight: 1
        $x_1_12 = "49VL870G9BAtC2P" ascii //weight: 1
        $x_1_13 = "Qtp7YqBTeFE" ascii //weight: 1
        $x_1_14 = "NNBew109WzG" ascii //weight: 1
        $x_1_15 = "Itx6QQRYNB" ascii //weight: 1
        $x_1_16 = "l8kOKD" ascii //weight: 1
        $x_1_17 = "Q9qyFqqHSw6IxiSeNKVep+H6w673VrM" ascii //weight: 1
        $x_1_18 = "Qp76XxiAXCGCetr6wuGmV8BH" ascii //weight: 1
        $x_1_19 = "IZw8NBv09ih5JBafESpNsqLy" ascii //weight: 1
        $x_1_20 = "fJX7A+H50SoINszgM6EMoA" ascii //weight: 1
        $x_1_21 = "Y5TIMoMFl/a6Z0uTs7yl2B" ascii //weight: 1
        $x_1_22 = "ZxkLXT2Dz23nv7t1Td5u" ascii //weight: 1
        $x_1_23 = "ZxkLQDzUW3hzULA" ascii //weight: 1
        $x_1_24 = "qtbfjYzs1aH" ascii //weight: 1
        $x_1_25 = "+xIUsghj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

