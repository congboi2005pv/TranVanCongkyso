🔐 Giới thiệu đề tài: Ứng dụng Web truyền file dữ liệu có ký số bằng RSA
Trong thời đại số hóa, việc truyền tải dữ liệu qua Internet đặt ra nhiều rủi ro về an toàn và toàn vẹn thông tin. Đề tài này xây dựng một ứng dụng web cho phép người dùng tải lên, ký số và truyền file dữ liệu một cách an toàn. Ứng dụng sử dụng thuật toán RSA kết hợp băm SHA-512 để thực hiện ký số, giúp đảm bảo rằng nội dung file không bị thay đổi và xác minh được người gửi.

Người dùng có thể tải file lên để hệ thống tự động tạo chữ ký số bằng khóa riêng RSA, sau đó tải về và xác minh chữ ký bằng khóa công khai tương ứng. Giao diện web được xây dựng bằng Flask và dễ sử dụng, phù hợp để mô phỏng quy trình ký số trong các hệ thống bảo mật cơ bản.
