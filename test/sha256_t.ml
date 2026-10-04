open Soundcheck_core

let expect source expected =
  let actual = Sha256.string source in
  if actual <> expected then
    failwith (Printf.sprintf "SHA-256 vector failed: expected %s, got %s" expected actual)

let () =
  expect ""
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  expect "abc"
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  expect "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
  expect
    ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     ^ "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";
  expect (String.make 1_000_000 'a')
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
  List.iter
    (fun (size, expected) ->
      expect (String.init size (fun index -> Char.chr (index mod 256))) expected)
    [ (55, "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59");
      (64, "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108");
      (129, "5099c6a56203f9687f7d33f4bfdf576d31dc91f6b695ecea38b2770c87631135") ];
  let path = Filename.temp_file "soundcheck-sha256-" ".bin" in
  Fun.protect ~finally:(fun () -> Sys.remove path) (fun () ->
      List.iter
        (fun size ->
          let source = String.init size (fun index -> Char.chr (index mod 256)) in
          let channel = open_out_bin path in
          output_string channel source;
          close_out channel;
          match Sha256.file path with
          | Ok hash when hash = Sha256.string source -> ()
          | _ -> failwith "SHA-256 file hashing changed binary input bytes")
        [ 0; 55; 56; 63; 64; 65; 127; 128; 129 ]);
  match Sha256.file path with
  | Error _ -> ()
  | Ok _ -> failwith "hashing a missing file must fail"
