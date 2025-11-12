rule Trojan_Win64_Radthief_MR_2147948866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.MR!MTB"
        threat_id = "2147948866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c0 2e 74 68 65 6d 69 64 61 00 ?? ?? 00 00 70 09 ?? ?? ?? ?? ?? ?? 42 06}  //weight: 3, accuracy: Low
        $x_2_2 = {60 20 20 20 20 20 20 20 20 44 65 05 00 00 e0 02 00 00 34 04 00 00 86 01}  //weight: 2, accuracy: High
        $x_5_3 = {c0 20 20 20 20 20 20 20 20 98 69 00 00 00 f0 08 00 00 32 00 00 00 0e 06}  //weight: 5, accuracy: High
        $x_5_4 = {40 00 00 c0 2e 74 68 65 6d 69 64 61 ?? ?? ?? ?? ?? 70 09 ?? ?? ?? ?? ?? ?? 42 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_KK_2147951993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.KK!MTB"
        threat_id = "2147951993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {49 89 d0 48 f7 e9 48 01 ca 48 d1 fa 49 89 c9 48 c1 f9 ?? 48 29 ca 48 8d 14 52 4d 89 ca 49 29 d1 49 39 f0}  //weight: 20, accuracy: Low
        $x_10_2 = {49 89 d0 48 f7 ea 48 c1 fa ?? 48 69 d2 ?? ?? 00 00 4d 89 c1 49 29 d0 49 8d 90 ?? ?? 00 00 48 39 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_MK_2147952111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.MK!MTB"
        threat_id = "2147952111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {45 0f b6 23 45 84 e4 ?? ?? 4c 8d 6e 01 0f 1f 44 00 00 4c 39 e9 ?? ?? 44 88 64 24 43 4c 89 9c 24 c8 00 00 00 48 89 d8 4c 89 eb bf 01}  //weight: 15, accuracy: Low
        $x_10_2 = {48 8d 3c 30 83 3f 00 ?? ?? 8b 7f 04 85 ff ?? ?? 4c 8d 47 f8 48 8d 34 30 48 8d 76 08 49 d1 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_ARD_2147952321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.ARD!MTB"
        threat_id = "2147952321"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 89 d0 48 f7 e9 48 01 ca 48 d1 fa 49 89 c9 48 c1 f9 3f 48 29 ca 48 8d 14 52 4d 89 ca 49 29 d1}  //weight: 2, accuracy: High
        $x_3_2 = {48 89 c7 48 b8 9e ef a7 c6 4b 37 89 41 49 89 d0 48 f7 ea 48 c1 fa 07 48 69 d2 f4 01 00 00 4d 89 c1 49 29 d0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_ARDT_2147952921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.ARDT!MTB"
        threat_id = "2147952921"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 74 24 ?? 48 89 c7 48 b8 9e ef a7 c6 4b 37 89 41 49 89 d0 48 f7 e9 48 c1 fa 07 48 69 d2 f4 01 00 00 49 89 c9 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_NKB_2147953785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.NKB!MTB"
        threat_id = "2147953785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "K.X]_D a.9.X_C.J.z.f_Y_c_N5\\.C s.r_w.8 A x.cF" ascii //weight: 2
        $x_1_2 = "u_u7 gE_MH m%?_M.x.e.PY1.O.w$.O.o Q_Jc.4_Y G.J M.R N.B.D k.E.TG.5d_r.Q d.g05.FP_d" ascii //weight: 1
        $x_1_3 = "m.E_G.u_b.FQ.hxD.2C f_g.R.de qR_A.u.D.t.K-.Qg$_OJd.S_G" ascii //weight: 1
        $x_1_4 = "4_Po[ex.E_Z_h S.I O.oh.w.Of.j_E J gQ W_u.h.a.G.8_M.D.W_QO_p" ascii //weight: 1
        $x_1_5 = "_hJ.iV x.vjq(-.r lE_o.u lPTz l T.9d.h" ascii //weight: 1
        $x_1_6 = "u_o!_Yj_V.U j G,v_H.O\\.e_w|_VS" ascii //weight: 1
        $x_1_7 = "y_IE B C h.k& q.6.i6 p1.v.F_o_S.y_Z R.r.I A_r.Ds_n.fn.k.u.n.q_v_b_L" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_AHD_2147954428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.AHD!MTB"
        threat_id = "2147954428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 89 d1 48 f7 eb 48 8d 34 13 48 c1 fe ?? 48 8d 34 b6 49 89 d8 48 29 f3 0f 57 c0 f2 48 0f 2a c3}  //weight: 20, accuracy: Low
        $x_30_2 = {4c 89 c9 49 d3 e0 4c 8d 5f 01 48 83 f9 ?? 4d 19 c9 4d 21 c8 41 b9 ?? ?? ?? ?? 4d 09 c8}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_NR_2147956501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.NR!MTB"
        threat_id = "2147956501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 39 41 8b 40 ?? 24 01 74 2c 49 83 78 ?? 00 74 25 48 c7 44 24 08 00 00 00 00 48 8b 44 24 08 49 89 40 ?? 8b 05 ba 4d 1e 00 d1 e8 a8 01 74 0c}  //weight: 2, accuracy: Low
        $x_1_2 = {ba 68 1e 00 48 8b 01 ff 50 ?? 48 8b d7 48 8b c8 4c 8b 00 4d 8b 48 ?? 44 8b c3 48 8b 5c 24 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_ARF_2147956729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.ARF!MTB"
        threat_id = "2147956729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d1 48 89 f7 4c 89 ce e8 ?? ?? ?? ?? 4c 8d 4b 01 48 8b 54 24 48 44 0f b6 54 24 47 48 89 c3 48 89 ce 48 8b 84 24 ?? 2c 09 00 48 8b 4c 24 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_GVB_2147957111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.GVB!MTB"
        threat_id = "2147957111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 8b 08 48 31 d9 48 89 48 20 48 8d 05 [0-18] 48 8b 44 24 58 48 8b 4c 24 38 48 8b 5c 24 60 eb 11}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8b 70 18 48 85 f6 74 13 48 8b 11 48 8b 0a 48 ff c3 48 89 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_AKR_2147957323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.AKR!MTB"
        threat_id = "2147957323"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 48 8d 0d eb 22 00 00 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 15 73 1d 00 00 48 8b d8 ff 15 ?? ?? ?? ?? 48 8d 15 eb 22 00 00 48 8b cb 48 89 05 c1 48 00 00 ff 15 ?? ?? ?? ?? 48 89 05 bc 48 00 00 33 c0 48 83 c4 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

