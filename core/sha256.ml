(* SHA-256 uses 32-bit modular arithmetic throughout. Keeping it here avoids
   adding a platform-specific hashing executable to the verifier's runtime. *)

let constants =
  [| 0x428a2f98l; 0x71374491l; 0xb5c0fbcfl; 0xe9b5dba5l;
     0x3956c25bl; 0x59f111f1l; 0x923f82a4l; 0xab1c5ed5l;
     0xd807aa98l; 0x12835b01l; 0x243185bel; 0x550c7dc3l;
     0x72be5d74l; 0x80deb1fel; 0x9bdc06a7l; 0xc19bf174l;
     0xe49b69c1l; 0xefbe4786l; 0x0fc19dc6l; 0x240ca1ccl;
     0x2de92c6fl; 0x4a7484aal; 0x5cb0a9dcl; 0x76f988dal;
     0x983e5152l; 0xa831c66dl; 0xb00327c8l; 0xbf597fc7l;
     0xc6e00bf3l; 0xd5a79147l; 0x06ca6351l; 0x14292967l;
     0x27b70a85l; 0x2e1b2138l; 0x4d2c6dfcl; 0x53380d13l;
     0x650a7354l; 0x766a0abbl; 0x81c2c92el; 0x92722c85l;
     0xa2bfe8a1l; 0xa81a664bl; 0xc24b8b70l; 0xc76c51a3l;
     0xd192e819l; 0xd6990624l; 0xf40e3585l; 0x106aa070l;
     0x19a4c116l; 0x1e376c08l; 0x2748774cl; 0x34b0bcb5l;
     0x391c0cb3l; 0x4ed8aa4al; 0x5b9cca4fl; 0x682e6ff3l;
     0x748f82eel; 0x78a5636fl; 0x84c87814l; 0x8cc70208l;
     0x90befffal; 0xa4506cebl; 0xbef9a3f7l; 0xc67178f2l |]

let ( +! ) = Int32.add
let ( ^! ) = Int32.logxor
let ( &! ) = Int32.logand

let rotate value bits =
  Int32.logor (Int32.shift_right_logical value bits)
    (Int32.shift_left value (32 - bits))

let compress state block =
  let words = Array.make 64 0l in
  for index = 0 to 15 do
    let word = ref 0l in
    for byte = 0 to 3 do
      word := Int32.logor (Int32.shift_left !word 8)
          (Int32.of_int (Char.code (Bytes.get block (4 * index + byte))))
    done;
    words.(index) <- !word
  done;
  for index = 16 to 63 do
    let left = words.(index - 15) and right = words.(index - 2) in
    let small0 = rotate left 7 ^! rotate left 18
        ^! Int32.shift_right_logical left 3 in
    let small1 = rotate right 17 ^! rotate right 19
        ^! Int32.shift_right_logical right 10 in
    words.(index) <- words.(index - 16) +! small0
        +! words.(index - 7) +! small1
  done;
  let work = Array.copy state in
  for index = 0 to 63 do
    let a = work.(0) and b = work.(1) and c = work.(2) and d = work.(3)
    and e = work.(4) and f = work.(5) and g = work.(6) and h = work.(7) in
    let big1 = rotate e 6 ^! rotate e 11 ^! rotate e 25 in
    let choose = (e &! f) ^! (Int32.lognot e &! g) in
    let temp1 = h +! big1 +! choose +! constants.(index) +! words.(index) in
    let big0 = rotate a 2 ^! rotate a 13 ^! rotate a 22 in
    let majority = (a &! b) ^! (a &! c) ^! (b &! c) in
    work.(0) <- temp1 +! big0 +! majority;
    work.(1) <- a;
    work.(2) <- b;
    work.(3) <- c;
    work.(4) <- d +! temp1;
    work.(5) <- e;
    work.(6) <- f;
    work.(7) <- g
  done;
  for index = 0 to 7 do
    state.(index) <- state.(index) +! work.(index)
  done

let digest read =
  let state =
    [| 0x6a09e667l; 0xbb67ae85l; 0x3c6ef372l; 0xa54ff53al;
       0x510e527fl; 0x9b05688cl; 0x1f83d9abl; 0x5be0cd19l |]
  in
  let block = Bytes.make 64 '\000' in
  let length = ref 0L in
  let rec blocks () =
    let count = read block in
    length := Int64.add !length (Int64.of_int count);
    if count = 64 then begin
      compress state block;
      blocks ()
    end else begin
      Bytes.fill block count (64 - count) '\000';
      Bytes.set block count '\128';
      if count >= 56 then begin
        compress state block;
        Bytes.fill block 0 64 '\000'
      end;
      let bits = Int64.mul !length 8L in
      for byte = 0 to 7 do
        Bytes.set block (63 - byte)
          (Char.chr
             (Int64.to_int
                (Int64.logand
                   (Int64.shift_right_logical bits (8 * byte)) 255L)))
      done;
      compress state block
    end
  in
  blocks ();
  Array.to_list state |> List.map (Printf.sprintf "%08lx") |> String.concat ""

let string source =
  let offset = ref 0 in
  digest (fun block ->
      let count = min 64 (String.length source - !offset) in
      Bytes.blit_string source !offset block 0 count;
      offset := !offset + count;
      count)

let file path =
  try
    let channel = open_in_bin path in
    let hash =
      Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
          digest (fun block ->
              let rec fill offset =
                if offset = 64 then offset
                else
                  match input channel block offset (64 - offset) with
                  | 0 -> offset
                  | count -> fill (offset + count)
              in
              fill 0))
    in
    Ok hash
  with Sys_error reason -> Error reason
