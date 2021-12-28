..
    Copyright 2019,2020 NXP


.. highlight:: bat

.. _ex-sss-ecdaa:

=======================================================================
 ECDAA Example
=======================================================================

This project demonstrates Elliptic Curve Cryptography ECDAA sign operation
using SSS APIs.

Refer - :file:`simw-top/sss/ex/ecdaa/ex_sss_ecdaa.c`

Prerequisites
=======================================================================

- Build Plug & Trust middleware stack. (Refer :ref:`building`)


About the Example
=======================================================================
This example does a elliptic curve cryptography signing and verify operation.

It uses the following APIs and data types:
  - :cpp:func:`sss_asymmetric_context_init()`
  - :cpp:enumerator:`kAlgorithm_SSS_ECDAA` from :cpp:type:`sss_algorithm_t`
  - :cpp:enumerator:`kMode_SSS_Sign` from :cpp:type:`sss_mode_t`
  - :cpp:func:`sss_asymmetric_sign_digest()`


Console output
=======================================================================


If everything is successful, the output will be similar to:

.. literalinclude:: out_ex_ecdaa.rst.txt
   :start-after: sss   :WARN :!!!Not recommended for production use.!!!


