# Third-party analytics assets

Sentinel downloads these fixed, hash-verified model assets into the case-data
model cache on first use. They are not stored in acquired evidence.

## OpenCV Zoo NanoDet

- Asset: `object_detection_nanodet_2022nov.onnx`
- Purpose: COCO object detection
- License: Apache License 2.0
- Source: <https://github.com/opencv/opencv_zoo/tree/main/models/object_detection_nanodet>
- Expected SHA-256: `4b82da9944b88577175ee23a459dce2e26e6e4be573def65b1055dc2d9720186`

## OpenCV Zoo YuNet

- Asset: `face_detection_yunet_2023mar.onnx`
- Purpose: face detection/indexing only
- License: MIT
- Source: <https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet>
- Expected SHA-256: `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4`

Model output is treated as an observation. Sentinel does not perform face
recognition, name a person, or make a biometric identity claim.
