package com.example.demo.manager;

import com.example.demo.dao.DepartmentRepository;
import com.example.demo.dao.entity.Department;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class DepartmentManager {

    private final DepartmentRepository departmentRepository;

    @Autowired
    public DepartmentManager(DepartmentRepository departmentRepository) {
        super();
        this.departmentRepository = departmentRepository;
    }

    public Optional<Department> findDepartmentById(Long id) {

        return departmentRepository.findById(id);
    }

    public Iterable<Department> findAllDepartments() {

        return departmentRepository.findAll();
    }

    public Department saveDepartment(Department dept) {

        return departmentRepository.save(dept);
    }

    public void deleteDepartmentById(Long id) {

        departmentRepository.deleteById(id);
    }
}
