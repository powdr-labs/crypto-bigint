use crypto_bigint::{
    const_monty_form, impl_modulus,
    modular::{
        BoxedMontyForm, BoxedMontyParams, ConstMontyForm, ConstMontyParams, MontyForm, MontyParams,
    },
    BoxedUint, Limb, Odd, Uint, U256,
};
use crypto_bigint::{powdr, MultiExponentiate};
use powdr_riscv_runtime;
use powdr_riscv_runtime::{
    arith::{modmul_256_u32_le, modmul_256_u8_le},
    io::read,
};

fn main() {
    // In the Powdr zkVM 256-bit numbers are represented in standard form.
    // Therefore ConstMontyForm type shouldn't convert such numbers to Montgomery form, i.e. (number * R) % modulus.
    // Instead, it simply calculates number % modulus.

    // ConstMontyForm tests
    impl_modulus!(
        Modulus,
        U256,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    );
    let values_uint_input = vec![
        U256::from(105u64),
        U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"),
    ];
    let values_uint_output_expected = vec![U256::from(105u64), U256::from(1u64)];

    // This block indirectly tests `from_integer()` and `new()`, because `const_monty_form!()` uses them.
    for (i, value_uint) in values_uint_input.iter().enumerate() {
        let value = const_monty_form!(value_uint, Modulus);

        // Montgomery field should be the standard form in Powdr VM.
        assert_eq!(
            value.clone().to_montgomery(),
            values_uint_output_expected[i]
        );

        // Retrieved integer should be the standard form in Powdr VM.
        assert_eq!(value.retrieve(), values_uint_output_expected[i]);

        // Serde tests currently don't pass because there's no way to cast ConstMontyForm<Modulus, LIMBS> to ConstMontyForm<Modulus, 8>.
        // let value_encoded = bincode::serialize(&value).unwrap();
        // let value_decoded = bincode::deserialize(&value_encoded).unwrap();
        // assert_eq!(value, value_decoded);

        // x * x.inv() = 1
        let inv = value.inv().unwrap();
        let res = value * inv;
        assert_eq!(res.retrieve(), U256::ONE);

        // x * x.inv_vartime() = 1
        let inv_vartime = value.inv_vartime().unwrap();
        let res_vartime = value * inv_vartime;
        assert_eq!(res_vartime.retrieve(), U256::ONE);
    }

    // ((modulus * 2) * 2) mod modulus = 2
    let a = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let b = U256::from(2u64);
    assert_eq!(
        (const_monty_form!(a, Modulus) * const_monty_form!(b, Modulus)).retrieve(),
        U256::from(2u64)
    );

    // hex(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 *
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 %
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
    // = 1
    let a = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let b = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let res = const_monty_form!(a, Modulus) * const_monty_form!(b, Modulus);
    assert_eq!(res.retrieve(), U256::from(1u64));

    // Test `square()`.
    let square_res = const_monty_form!(a, Modulus).square();
    assert_eq!(square_res.retrieve(), U256::from(1u64));

    // a * a.inv() = 1
    let a = U256::from_be_hex("ff00000000000000000000000000000f00000000000000000000000000000002");
    let inv = const_monty_form!(a, Modulus).inv().unwrap();
    powdr_riscv_runtime::print!("inv: {}\n", inv.retrieve());
    // powdr_riscv_runtime::print!("a * a_inv: {}\n", (const_monty_form!(a, Modulus) * inv).retrieve());
    assert_eq!((const_monty_form!(a, Modulus) * inv).retrieve(), U256::ONE);

    // Test public constant `ONE`
    assert_eq!(ConstMontyForm::<Modulus, 8>::ONE.retrieve(), U256::ONE);

    // Test `pow()` and `pow_bounded_exp()`:
    // Both indirectly use `square_montgomery_form()` and `mul_montgomery_form()`,
    // which are accelerated by Powdr precompiles.
    // Test vectors directly taken from crypto-bigint.

    // Taken from `test_powmod()`:
    impl_modulus!(
        Modulus_2,
        U256,
        "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B"
    );
    let base =
        U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
    let base_mod = const_monty_form!(base, Modulus_2);
    let exponent =
        U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");
    let res = base_mod.pow(&exponent);
    let expected =
        U256::from_be_hex("3681BC0FEA2E5D394EB178155A127B0FD2EF405486D354251C385BDD51B9D421");
    assert_eq!(res.retrieve(), expected);

    // Taken from ConstMontyForm test `test_multi_exp_slice()`.
    // This test uses `multi_exponentiate()`, which indirectly uses `multi_exponentiate_montgomery_form_slice()`,
    // which is a function Powdr patches.
    // `multi_exponentiate()` is only ever used by ConstMontyForm.
    // Note that `multi_exponentiate_montgomery_form_slice()` also requires feature "alloc" enabled,
    // which is currently enabled for crypto-bigint in our guest Cargo.toml by default.
    let base2 =
        U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
    let base2_mod = const_monty_form!(base2, Modulus_2);
    let exponent2 =
        U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");
    let expected = base_mod.pow(&exponent) * base2_mod.pow(&exponent2);
    let bases_and_exponents = vec![(base_mod, exponent), (base2_mod, exponent2)];
    let res = ConstMontyForm::<Modulus_2, { U256::LIMBS }>::multi_exponentiate(
        bases_and_exponents.as_slice(),
    );
    assert_eq!(res, expected);

    // BoxedMontyForm tests
    let boxed_modulus = BoxedUint::from(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ));
    let boxed_params = BoxedMontyParams::new(boxed_modulus.to_odd().unwrap());

    let values_boxed_uint_input = vec![
        BoxedUint::from(U256::from(2u64)),
        BoxedUint::from(U256::from_be_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        )),
    ];
    let values_boxed_uint_output_expected = vec![
        BoxedUint::from(U256::from(2u64)),
        BoxedUint::from(U256::from(1u64)),
    ];

    for (i, val) in values_boxed_uint_input.iter().enumerate() {
        // Powdr VM patches will only run if both the modulus and the integer have 8 limbs (of 32 bits).
        assert_eq!(boxed_modulus.nlimbs(), 8);
        assert_eq!(val.nlimbs(), 8);
        // `new` and `new_with_arc` are very similar APIs except that the latter takes Arc<BoxedMontyParams>.
        // Need to test both.
        let boxed_monty = BoxedMontyForm::new(val.clone(), boxed_params.clone());
        let boxed_monty_arc_param =
            BoxedMontyForm::new_with_arc(val.clone(), boxed_params.clone().into());

        // Montgomery field should be the standard form in Powdr VM.
        assert_eq!(
            boxed_monty.clone().to_montgomery(),
            values_boxed_uint_output_expected[i]
        );
        assert_eq!(
            boxed_monty_arc_param.clone().to_montgomery(),
            values_boxed_uint_output_expected[i]
        );

        // Retrieved integer should be the standard form in Powdr VM.
        assert_eq!(boxed_monty.retrieve(), values_boxed_uint_output_expected[i]);
        assert_eq!(
            boxed_monty_arc_param.retrieve(),
            values_boxed_uint_output_expected[i]
        );
    }

    // ((modulus * 2) * 2) mod modulus = 2
    let a = BoxedUint::from(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    ));
    let b = BoxedUint::from(U256::from_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000002",
    ));
    // powdr_riscv_runtime::print!("result boxed {:?}\n", (BoxedMontyForm::new(a, boxed_params.clone()) * BoxedMontyForm::new(b, boxed_params.clone())).retrieve());
    assert_eq!(
        (BoxedMontyForm::new(a, boxed_params.clone())
            * BoxedMontyForm::new(b, boxed_params.clone()))
        .retrieve(),
        BoxedUint::from(U256::from(2u64))
    );

    // hex(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 *
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 %
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
    // = 1
    let a = BoxedUint::from(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    ));
    let b = BoxedUint::from(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    ));
    let res =
        BoxedMontyForm::new(a, boxed_params.clone()) * BoxedMontyForm::new(b, boxed_params.clone());
    assert_eq!(res.retrieve(), BoxedUint::from(U256::from(1u64)));

    // a * a.inv() = 1
    let a = BoxedUint::from(U256::from_be_hex(
        "ff00000000000000000000000000000f00000000000000000000000000000002",
    ));
    let a_monty = BoxedMontyForm::new(a, boxed_params.clone());
    let a_monty_inv = a_monty.invert().unwrap(); // uses `inv()`
    assert_eq!(
        (a_monty_inv * a_monty.clone()).retrieve(),
        BoxedUint::from(U256::ONE)
    );

    // a * a.inv_vartime() = 1
    let a_monty_inv_vartime = a_monty.invert_vartime().unwrap();
    assert_eq!(
        (a_monty_inv_vartime * a_monty).retrieve(),
        BoxedUint::from(U256::ONE)
    );

    // Test `one()`.
    assert_eq!(
        BoxedMontyForm::one(boxed_params.clone()).to_montgomery(),
        BoxedUint::from(U256::ONE)
    );

    // MontyForm tests
    let monty_mod =
        U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let monty_param = MontyParams::new(monty_mod.to_odd().unwrap());

    for (i, val) in values_uint_input.iter().enumerate() {
        let val_monty = MontyForm::new(val, monty_param.clone());

        // Montgomery field should be the standard form in Powdr VM.
        assert_eq!(val_monty.to_montgomery(), values_uint_output_expected[i]);

        // Retrieved integer should be the standard form in Powdr VM.
        assert_eq!(val_monty.retrieve(), values_uint_output_expected[i]);
    }

    // ((modulus * 2) * 2) mod modulus = 2
    let a = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let b = U256::from(2u64);
    assert_eq!(
        (MontyForm::new(&a, monty_param.clone()) * MontyForm::new(&b, monty_param.clone()))
            .retrieve(),
        U256::from(2u64)
    );

    // hex(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 *
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 %
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
    // = 1
    let a = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let b = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let res = MontyForm::new(&a, monty_param.clone()) * MontyForm::new(&b, monty_param.clone());
    assert_eq!(res.retrieve(), U256::from(1u64));

    // Test `square()`
    let res_square = MontyForm::new(&a, monty_param.clone()).square();
    assert_eq!(res_square.retrieve(), U256::from(1u64));

    // // a * a.inv() = 1
    let a = U256::from_be_hex("ff00000000000000000000000000000f00000000000000000000000000000002");
    let inv = MontyForm::new(&a, monty_param.clone()).inv().unwrap();
    powdr_riscv_runtime::print!("inv: {}\n", inv.retrieve());
    assert_eq!(
        (MontyForm::new(&a, monty_param.clone()) * inv).retrieve(),
        U256::ONE
    );

    // Test public constant function `one()`
    assert_eq!(
        MontyForm::one(monty_param.clone()).to_montgomery(),
        U256::ONE
    );

    // Test `pow()` and `pow_bounded_exp()`:
    // Both indirectly use `square_montgomery_form()` and `mul_montgomery_form()`,
    // which are accelerated by Powdr precompiles.
    // Test vectors directly taken from crypto-bigint.

    // Taken from `test_powmod()` from ConstMontyForm:
    // Additional notes:
    //    `multi_exponentiate_montgomery_form_array()` is indirectly tested here by `MontyForm::pow()`,
    //    which calls `MontyForm::pow_bounded_exp()`, which calls `pow_montgomery_form()`,
    //    which calls `multi_exponentiate_montgomery_form_array()`.
    let monty_mod =
        U256::from_be_hex("9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B");
    let monty_param = MontyParams::new(monty_mod.to_odd().unwrap());
    let base =
        U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
    let base_mod = MontyForm::new(&base, monty_param.clone());
    let exponent =
        U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");
    let res = base_mod.pow(&exponent);
    let expected =
        U256::from_be_hex("3681BC0FEA2E5D394EB178155A127B0FD2EF405486D354251C385BDD51B9D421");
    assert_eq!(res.retrieve(), expected);

    // Uint tests: only tests `mul_mod_special()`, which is not used by any MontyForm types.
    // Note that `a.mul_mod_special(b, c)` calculates (a * b) % (U256::MAX + 1 - c),
    // where c can be represented by one limb of 32 bits.
    // Therefore, the following test does the calculation:
    // hex(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552 *
    // 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 %
    // (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff + 1 - 37))
    let a = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let b = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mod_limb = Limb::from(37u32);
    let res = a.mul_mod_special(&b, mod_limb);
    assert_eq!(
        res,
        U256::from_be_hex("004365D41D819D719A02FC8E5D724AB28A58CF513D90BD29606CC5852441ADEE")
    );

    // BoxedUint tests:
    let a = BoxedUint::from(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    ));
    let b = BoxedUint::from(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ));
    let mod_limb = Limb::from(37u32);
    let res = a.mul_mod_special(&b, mod_limb);
    assert_eq!(
        res,
        BoxedUint::from(U256::from_be_hex(
            "004365D41D819D719A02FC8E5D724AB28A58CF513D90BD29606CC5852441ADEE"
        ))
    );

    // Wrapped Powdr syscall tests
    let res = powdr::modmul_boxed_uint_256(
        &BoxedUint::from(U256::from_be_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        )),
        &BoxedUint::from(U256::from(2u64)),
        &BoxedUint::from(U256::from_be_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )),
    );
    assert_eq!(res, BoxedUint::from(U256::from(2u32)));

    let res = powdr::modmul_uint_256(
        &U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"),
        &U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"),
        &U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    );
    assert_eq!(res, U256::from(1u32));
}
