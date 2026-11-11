# DỰ TRỮ / THEO DÕI — phương án sau phản biện

## Các điểm đã chốt sau phản biện độc lập

- Dùng `ttk.Notebook` hai tab, bỏ splitter kéo MODEL/DỰ TRỮ; THEO DÕI tối đa 7 hàng và thanh cuộn khi màn hình thấp.
- Thanh trạng thái dùng chung nằm ngoài Notebook để lỗi/lưu/sao chép của tab Dự trữ không bị ẩn.
- Cùng đường DPAPI strict cho `spare_models` và `watch_keys`; bản ghi đang khóa không được gửi request, ciphertext không được mất khi sửa metadata.
- Mỗi watch có ID ngẫu nhiên bền vững và revision. Mỗi lô có run ID và cờ dừng; sửa/xóa/tắt Auto loại bỏ callback cũ.
- Watch chỉ gửi request theo key chính xác người dùng đã lưu, không gọi `inherit_key()`.
- Auto và thử tay dùng chung worker tuần tự, timeout 20 giây mỗi request. Auto chỉ nhắm `watch_keys`; vòng tự thử slot cũ bị bỏ.
- Sau hai lỗi xác thực/quyền truy cập 401/403 liên tiếp, tạm tắt Auto dòng đó và ghi lý do; lỗi mạng/429/5xx dùng backoff tối đa 60 phút, không gọi key chết.
- Không lưu raw provider body hoặc chuỗi exception có thể chứa secret. Kết quả có category và HTTP code riêng.
- Fit dựa theo nội dung Tổng quan, không theo requested width/height lớn nhất của tab ẩn. Test phải chọn tab Dự trữ trước thao tác bảng.
- Không thêm đường đưa THEO DÕI vào slot; chỉ có lưu độc lập và sao chép từ dự trữ/slot.

Phản biện là cổng thiết kế, không phải bằng chứng code đã đạt yêu cầu. Các mục trên phải được kiểm chứng bằng test và UI thực tế cô lập.

## Phạm vi người dùng yêu cầu

- Chuyển DỰ TRỮ khỏi dashboard sang tab riêng, dùng toàn vùng nội dung.
- Thay vị trí cũ bằng THEO DÕI, tối đa 7 key, không tìm kiếm.
- Auto thử chỉ chạy trên THEO DÕI. DỰ TRỮ giữ thử thủ công.
- Giữ mọi sửa lỗi UI đang có; không triển khai bản cũ trong lúc mở rộng phạm vi.

## Ranh giới bắt buộc

- Hai tab: Tổng quan (MODEL/VẬN HÀNH và THEO DÕI), Dự trữ (bảng và thao tác hiện có).
- DỰ TRỮ tiếp tục là danh sách model ứng viên, không phải danh sách key cần gửi request định kỳ.
- Mỗi dòng THEO DÕI là một credential có ID bền vững, tên gợi nhớ, endpoint, key và một model dùng để thử. Hai key khác nhau cùng endpoint/model không ghi đè nhau.
- UI và backend cùng chặn thêm dòng thứ 8; sửa dòng hiện có khi đủ 7 vẫn được phép.
- THEO DÕI không kế thừa key ngầm theo Base URL. Lấy từ dự trữ/slot là thao tác người dùng chọn rõ ràng và sao chép độc lập.
- Không tự đưa 7 dòng dự trữ đầu tiên vào THEO DÕI. Không tự bật lại Auto thử cũ vì tập mục tiêu đã đổi.
- Lưu, sửa, xóa, thử key và thêm vào THEO DÕI không ghi `ov.conf`, không chuyển slot, không khởi động lại server.
- Đưa vào slot tiếp tục đi qua `apply_conf_edit` và kiểm định hiện có; theo dõi thành công không đồng nghĩa provider an toàn.

## Đề xuất UX

- Hiển thị số lượng `0/7`, tên gợi nhớ, model thử, trạng thái gần nhất, độ trễ, lần thử và Auto theo từng dòng.
- Có nút thêm, sửa/double-click, thử ngay, tạm dừng và xóa có xác nhận; menu lấy từ dự trữ/slot theo lựa chọn rõ ràng.
- Auto có công tắc tổng mặc định tắt và trạng thái cho từng key. Chỉ chạy khi cả hai cho phép.
- Không hiện key thô trong bảng, log, tooltip hay chẩn đoán. Editor che key; copy theo cơ chế hết hạn clipboard hiện có.
- Kết quả thử là bằng chứng cho key + endpoint + model tại thời điểm thử, không kết luận toàn bộ model hay quota còn lại.
- 429 là giới hạn tần suất/quota, 401 là lỗi xác thực, 403 là quyền truy cập, 404 là endpoint/model, lỗi mạng/timeout không phải bằng chứng key hỏng.
- Thông báo chỉ khi đổi trạng thái để tránh lặp. Không thêm biểu đồ hoặc kho lịch sử lớn vào vòng này.

## Lịch thử và an toàn

- Tuần tự, một lô duy nhất, không chồng lô Auto và thử tay trên cùng watchlist.
- Chụp immutable snapshot ID + phiên bản credential trước khi gửi; bỏ kết quả trễ nếu dòng đã sửa/xóa.
- Timeout hữu hạn; cờ dừng chặn request tiếp theo. Tắt Auto không thể thu hồi request đã gửi.
- Dùng đồng hồ monotonic cho lịch; giãn chu kỳ khi 429 hoặc lỗi mạng và hiển thị lần thử kế tiếp.
- Request thử ngắn, nội dung giả, không đưa dữ liệu OpenViking vào request. UI giải thích request có thể tiêu token.
- `monitor.json` lưu danh sách mới riêng, áp DPAPI strict và giữ ciphertext nguyên vẹn khi key không đổi/đang khóa như DỰ TRỮ.

## Nền tảng và cổng xác minh

- Vòng `auto_probe_tick()` trước đây thử slot trong `ov.conf`, không thử `spare_models`; bản mới đã bỏ vòng này, chỉ có lịch riêng của THEO DÕI.
- `suite_bootstrap.py` trước đây không tự cô lập `USERPROFILE` khi chạy trực tiếp; test subprocess sentinel đã tái hiện lỗi, sau vá đã đạt `SUITE_ISOLATION_OK`.
- Runner với tính năng mới và hồi quy phản biện: 59/59 suite PASS, không skip/timeout. `SELF_CHECK_OK`; ma trận dashboard và slot editor đạt cả ba mức Tk scaling bên dưới.
- Hash/size/mtime của `ov.conf` và `monitor.json` không đổi qua các đợt test có guard. Chưa quy kết được nguồn ghi lịch sử bằng bằng chứng process/file-write.
- Ảnh cửa sổ Tk cô lập dùng dữ liệu giả cho cả hai tab: tối thiểu 3 hàng THEO DÕI đầy đủ, có cuộn đến hàng 7, toàn bộ nút Dự trữ đủ chỗ.

## Các phát hiện phản biện đã tái hiện và sửa

- Form Sửa chỉ gửi ID và trường người dùng nhập, không chép lại snapshot Auto cũ. Test mở form, nhận hai lỗi 401 trong lúc form còn mở rồi Lưu; trạng thái Auto tắt/lý do/lịch sử được giữ nguyên.
- Không nhận chuỗi `dpapi:` nhập trực tiếp qua watch store; người dùng nhập API key hoặc `${BIẾN_MÔI_TRƯỜNG}`. Ciphertext chỉ được xử lý qua đường load DPAPI strict.
- `watch_keys: null` được chuẩn hóa rỗng; dữ liệu hỏng kiểu/ID/credential/thời điểm khóa Auto và khóa lưu state, có cảnh báo nhưng không xóa hoặc ghi đè dữ liệu gốc. Không tự lọc mất key để làm test xanh.

## Cổng nghiệm thu dự kiến

- Tối đa 7, sửa khi đủ, hai key cùng endpoint/model, DPAPI locked, save failure, delete/edit trong lúc thử, stop/close, Auto tắt sau migration.
- DỰ TRỮ không Auto; không truy vấn provider khi chỉ mở tab, lưu hoặc tải state.
- UI có bề ngang 880/996/1020/1100/1400 tại Tk scaling 1.333333 / 1.666667 / 2.0 (Windows 100% / 125% / 150%); auto-fit chiều cao theo màn hình. Không tuyên bố Windows 200% từ Tk scaling 2.0. Tab DỰ TRỮ không chiếm chiều cao dashboard khi ẩn; bảng theo dõi không có thanh tìm kiếm.
- `ov.conf` không đổi sau toàn thao tác THEO DÕI; test profiles không ghi dữ liệu live.
- Phản biện độc lập trước triển khai; sync qua `scripts/monitor_sync.py` với backup/rollback sau khi đủ cổng.

## Kết quả nghiệm thu

- Phản biện xác nhận ba lỗi race/DPAPI/state: `passed=true`, không có lỗi logic hoặc bảo mật chặn. Gợi ý UX không được xem là bằng chứng lỗi đã sửa.
- Đối chiếu runner: đủ 59 suite, 59 PASS, không FAIL/SKIP/TIMEOUT. Chạy lại dashboard và slot editor tại cả ba mức Tk scaling nêu trên: 6/6 PASS; self-check đạt `SELF_CHECK_OK`.
- Đồng bộ source-only qua `monitor_sync.py`: receipt `applied`, backup xác minh hợp lệ, kế hoạch sau sync không còn drift. Không ghi đè `ov.conf` hoặc `monitor.json` trong bước triển khai.
- Mở bản live và chuyển qua lại hai tab: THEO DÕI trống 0/7, Auto tắt; DỰ TRỮ toàn chiều rộng, không Auto, hai hàng nút hiển thị đủ. Không thử key thật trong lượt QA.
- Phân biệt mốc dữ liệu: hai file dữ liệu nguyên byte qua bước source sync; sau khởi động GUI, `monitor.json` có thay đổi trạng thái migration/autofit. `ov.conf` vẫn nguyên SHA-256 và mtime. Không dùng hash để khẳng định mọi trường state hoặc key không đổi khi không có bản so sánh nội dung.
- Giữ nguyên PID OpenViking/AGFS, `/health` và `/ready` cùng HTTP 200; chỉ tiến trình Monitor được mở mới.
